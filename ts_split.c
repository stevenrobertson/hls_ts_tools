#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <assert.h>

typedef uint8_t ts_pkt_data[184];

typedef struct {
    unsigned int sync_byte                      : 8;    // 0x47
    unsigned int PID_hi                         : 5;
    unsigned int priority_flag                  : 1;
    unsigned int payload_unit_start_indicator   : 1;
    unsigned int transport_error_indicator      : 1;
    unsigned int PID_lo                         : 8;
    unsigned int continuity_counter             : 4;
    unsigned int adaptation_field_control       : 2;
    unsigned int transport_scramble_control     : 2;
    ts_pkt_data data;
} ts_pkt;

// Oh my goodness this is terrible.
typedef uint8_t pes_pkt_hdr[14];

typedef struct {
    ts_pkt *pat;        // Exact copies of the PAT and PMT.
    ts_pkt *pmt;        // This assumes PAT and PMT are both one packet long,
                        // which is fine for this project but not to spec.
                        // The continuity counter will be incremented directly
                        // on these data structures.

    pes_pkt_hdr pes;    // The PES header of the current AU.

    uint8_t *au_nalus;  // The undecoded NALUs comprising the current AU;
    size_t au_sz;       // buffer size;
    size_t au_o;        // and current write offset into buffer.

    uint8_t *sps_nalu;  // The undecoded NALUs containing the SPS and PPS pulled
    uint8_t *pps_nalu;  // from the stream.
    size_t sps_nalu_sz;
    size_t pps_nalu_sz;

    char *basename;     // Basename of output files.
    char *outdir;       // Output directory.

    int slice_num;      // Number of slices opened for writing thus far.
    FILE *out;          // Output .ts file.
    FILE *out_idx;      // Output PES index (see ts_retime.c).
    uint32_t out_pkts;  // Number of packets written in this slice.

    uint64_t head_pts;  // The PTS of the first (IDR) frame in this slice.

    ts_pkt opkt;        // Used during packetization
    int opkt_fill;
} write_st;

/* Verify that the PES header is as expected, and copy it to 'pes'. Copy any
 * NALU data into 'nal_start'. Returns the amount of data copied int
 * 'nal_start'.
 *
 * TODO: this will choke if DTS (or many other less-common settings) are used
 * in the PES header.
 */

size_t check_pes(uint8_t *nal_start, pes_pkt_hdr *pes,
                 const uint8_t *src, size_t sz) {
    assert(sz > 15);

    /* Start code as in spec (0x000001), stream_id of 0xe0 (video stream,
     * index 0), packet length of 0, original_or_copy set to 1, PTS_DTS_flags
     * set to 2 (PTS only), PES header length of 5, all other flags unset */
    const uint8_t expected[9] = {0, 0, 1, 0xe0, 0, 0, 0x81, 0x80, 5};
    assert(!bcmp(src, expected, 9));

    memcpy(pes, src, sizeof(pes_pkt_hdr));
    size_t cpsz = sz - sizeof(pes_pkt_hdr);
    memcpy(nal_start, ((uint8_t *) src) + sizeof(pes_pkt_hdr), cpsz);
    return cpsz;
}

/* Convert 5-byte padded PTS/DTS representation used in PES headers to
 * a uint64_t. */
uint64_t get_pts(const pes_pkt_hdr pes) {
    // TODO: does not check that PES header has a PTS (but that's done in
    // 'check_pts')

    // Avoid parenthapocalypse by converting here
    uint64_t p[5] = {pes[9], pes[10], pes[11], pes[12], pes[13]};
    return ( (p[0] & 0xe) << 30)
           + (p[1] << 22)
           +((p[2] & 0xf7) << 14)
           + (p[3] << 7)
           + (p[4] >> 1);
}

int nalu_check3(const uint8_t *a) {
    return a[0] == 0 && a[1] == 0 && a[2] == 1;
}

/* Given the index of an existing NALU start, return the index of the next
 * NALU start (the index of the first byte of the three-byte sequence
 * 0x000001), or 'sz' if none found before EOS. Caller is responsible for
 * removing 'leading_zero_8bits' at the start of a buffer.
 *
 * Note that this process will leave extra zero bytes at the end of the
 * nal_unit, according to Annex B, but since we just copy the NALs that's OK.
 */
size_t find_next_nalu(const uint8_t *au, size_t sz, size_t off) {
    assert(off + 3 < sz);
    assert(nalu_check3(au+off));
    off += 3;

    while (off + 3 < sz) {
        if (nalu_check3(au+off)) return off;
        off++;
    }
    return sz;
}

void flush_writer(write_st *w) {
    if (w->out) fclose(w->out);
    if (w->out_idx) fclose(w->out_idx);
    w->out = w->out_idx = NULL;
}

void write_idx(FILE *out_idx, uint32_t pkt_num, uint64_t pts_diff) {
    uint32_t out[2] = {pkt_num, (uint32_t) pts_diff};
    fwrite(out, sizeof(uint32_t), 2, out_idx);
}

void _write_pkt(write_st *w) {
    fwrite(&w->opkt, sizeof(ts_pkt), 1, w->out);
    w->out_pkts++;
    w->opkt_fill = 0;
    w->opkt.payload_unit_start_indicator = 0;
    w->opkt.continuity_counter++;
}

void put_pkt_data(write_st *w, const uint8_t *src, size_t sz) {
    if (w->opkt_fill + sz < sizeof(ts_pkt_data)) {
        memcpy(w->opkt.data + w->opkt_fill, src, sz);
        w->opkt_fill += sz;
        return;
    }

    size_t o = sizeof(ts_pkt_data) - w->opkt_fill;
    memcpy(w->opkt.data + w->opkt_fill, src, o);
    _write_pkt(w);

    while (sz - o >= sizeof(ts_pkt_data)) {
        memcpy(w->opkt.data, src + o, sizeof(ts_pkt_data));
        o += sizeof(ts_pkt_data);
        _write_pkt(w);
    }

    memcpy(w->opkt.data, src + o, sz - o);
    w->opkt_fill = sz - o;
}

void flush_pkt(write_st *w) {
    if (w->opkt_fill == 0) return;
    size_t diff = sizeof(ts_pkt_data) - w->opkt_fill;
    if (diff == 0) {
        _write_pkt(w);
        return;
    }

    // Need to insert an adaptation field at the head of the packe's data
    // section to pad it to full length
    w->opkt.adaptation_field_control = 3;
    memmove(w->opkt.data + diff, w->opkt.data, w->opkt_fill);

    w->opkt.data[0] = diff - 1;

    // Set all flags in the adaptation field to 0
    if (diff > 1) w->opkt.data[1] = 0;
    // Fill the remaining bytes with stuffing
    if (diff > 2) memset(w->opkt.data + 2, 0xff, diff - 2);

    _write_pkt(w);
}

void write_au(write_st *w) {
    const uint8_t three_zeros[3] = {0, 0, 0};

    int insert_sps_pps = 0;

    size_t o = 0;
    // Read past leading_zero_8bits and zero_byte
    while (o + 3 < w->au_o) {
        if (bcmp(w->au_nalus + o, three_zeros, 3)) break;
        o++;
    }

    // Ensure that the first NALU is an AUD
    assert(w->au_nalus[o+3] == 9);
    uint8_t primary_pic_type = w->au_nalus[5] >> 5;

    // Update off so it's pointing at the start of the first NALU after AUD
    o = find_next_nalu(w->au_nalus, w->au_o, o);

    if (primary_pic_type == 0) { // This is an IDR (I-frame), start a new file.
        // TODO: if there are, say, two consecutive I-frames, this will
        // produce a one-frame-long TS file for the first. Perhaps we should
        // buffer output and write out all GOPs that would be under a
        // particular (user-specified) duration, like 10s?

        if (!w->sps_nalu) {
            // Haven't read SPS or PPS; parse NALUs until we find them.

            size_t off = o;
            while (!w->sps_nalu || !w->pps_nalu) {
                // Stream bug: SPS or PPS missing from first NALU
                assert(off < w->au_o);

                size_t end = find_next_nalu(w->au_nalus, w->au_o, off);
                uint8_t nalu_type = w->au_nalus[off+3] & 0x1f;
                if (nalu_type == 7) {
                    w->sps_nalu_sz = end - off;
                    w->sps_nalu = malloc(w->sps_nalu_sz);
                    memcpy(w->sps_nalu, w->au_nalus + off, w->sps_nalu_sz);
                } else if (nalu_type == 8) {
                    w->pps_nalu_sz = end - off;
                    w->pps_nalu = malloc(w->pps_nalu_sz);
                    memcpy(w->pps_nalu, w->au_nalus + off, w->pps_nalu_sz);
                }
                off = end;
            }
        } else {
            // TODO: If SPS and PPS changed between stream start and now, this
            // will reset them. Doubt it will ever happen with our stuff, tho.
            insert_sps_pps = 1;
        }

        flush_writer(w);

        char buf[2048];
        snprintf(buf, 2047, "%s/%s-%02d.ts", w->outdir, w->basename, w->slice_num);
        assert(w->out = fopen(buf, "w"));
        snprintf(buf, 2047, "%s/%s-%02d.idx", w->outdir, w->basename, w->slice_num);
        assert(w->out_idx = fopen(buf, "w"));
        setbuffer(w->out, _IOFBF, 192512);  // LCM of 4096 and 188
        w->slice_num++;

        // TODO: do continuity codes need to be intact across multiple files
        // when read by most DSP libraries doing HLS? Should we be emitting
        // adaptation fields with the discontinuity flag set? (If we do this,
        // does it break gapless playback?) Read common demuxers for info
        fwrite(w->pat, sizeof(ts_pkt), 1, w->out);
        fwrite(w->pmt, sizeof(ts_pkt), 1, w->out);
        w->out_pkts = 2;

        w->head_pts = get_pts(w->pes);
    }

    // Next packet will contain PES header, add index entry
    write_idx(w->out_idx, w->out_pkts, get_pts(w->pes) - w->head_pts);

    w->opkt.sync_byte = 0x47;
    w->opkt.PID_lo = 0x40;      // TODO: still using a fixed PID here
    w->opkt.payload_unit_start_indicator = 1;
    w->opkt.adaptation_field_control = 1;
    // TODO: same stuff with continuity codes above
    assert(w->opkt_fill == 0);

    put_pkt_data(w, (uint8_t *) &w->pes, sizeof(pes_pkt_hdr));
    // Push the AUD NALU before anything else
    put_pkt_data(w, w->au_nalus, o);
    if (insert_sps_pps) {
        put_pkt_data(w, w->sps_nalu, w->sps_nalu_sz);
        put_pkt_data(w, w->pps_nalu, w->pps_nalu_sz);
    }
    put_pkt_data(w, w->au_nalus + o, w->au_o - o);
    flush_pkt(w);
}


int main(int argc, char *argv[]) {
    if (argc != 3) {
        printf("Usage: %s INFILE OUTDIR\n", argv[0]);
        return 1;
    }

    size_t pkts_fill = 0;
    size_t o = 0;
    const size_t pkts_sz = 256;
    ts_pkt *pkts = malloc(sizeof(ts_pkt) * pkts_sz);

    write_st *w = calloc(sizeof(write_st), 1);
    w->au_sz = 256 * sizeof(ts_pkt_data);
    w->au_nalus = malloc(w->au_sz);

    char *basename = strdup(argv[1]);
    int i;
    for (i = strlen(basename) - 1; i >= 0; i--) {
        if (basename[i] == '.') {
            basename[i] = '\0';
            break;
        }
    }
    for (; i > 0 && basename[i-1] != '/'; i--);
    w->basename = strdup(basename+i);
    free(basename);
    w->outdir = strdup(argv[2]);

    int reading_nals = 0;

    FILE *f = fopen(argv[1], "r");
    pkts_fill = fread(pkts, sizeof(ts_pkt), pkts_sz, f);

    while (pkts_fill - o > 0) {
        assert(pkts[o].sync_byte == 0x47);

        // Never deal with a packet that only has an adaptation field
        assert(pkts[o].adaptation_field_control != 2);

        if (reading_nals && pkts[o].payload_unit_start_indicator) {
            // Current PES packet is finished, flush and start the next one
            reading_nals = 0;
            write_au(w);
        }

        if (!reading_nals) {
            // C doesn't allow this to be declared inside the switch. THANKS C
            size_t adapt_off;
            assert(pkts[o].payload_unit_start_indicator);
            assert(pkts[o].transport_scramble_control == 0);

            assert(pkts[o].PID_hi == 0);
            switch (pkts[o].PID_lo) {
                case 0x00:
                    // We assume that the PAT never changes and only take the
                    // first one.
                    if (!w->pat) {
                        w->pat = calloc(sizeof(ts_pkt), 1);
                        memcpy(w->pat, pkts + o, sizeof(ts_pkt));
                    }
                    break;
                case 0x20:
                    // Ordinarily one would parse the PAT to determine the PID
                    // used for the PMT, but... lazy.
                    if (!w->pmt) {
                        w->pmt = calloc(sizeof(ts_pkt), 1);
                        memcpy(w->pmt, pkts + o, sizeof(ts_pkt));
                    }
                    break;
                case 0x40:
                    // Likewise, we assume video content has PID 0x40.
                    adapt_off = 0;
                    if (pkts[o].adaptation_field_control == 0x03) {
                        // TODO: we ignore these adaptation fields entirely
                        adapt_off = 1 + pkts[o].data[0];
                    }
                    w->au_o = check_pes(w->au_nalus, &w->pes,
                                        pkts[o].data + adapt_off,
                                        sizeof(ts_pkt_data) - adapt_off);
                    reading_nals = 1;
                    break;
                default:
                    assert(0);
            }
        } else {
            // reading_nals == 1, and current TS pkt PUSI unset
            int data_off = 0;
            if (w->au_o + sizeof(ts_pkt_data) >= w->au_sz) {
                w->au_sz *= 2;
                w->au_nalus = realloc(w->au_nalus, w->au_sz);
            }
            if (pkts[o].adaptation_field_control == 3) {
                uint8_t adaptation_field_length = pkts[o].data[0];
                if (adaptation_field_length > 0) {
                    // We don't (yet?) support any adaptation field flags
                    assert(pkts[o].data[1] == 0);
                }
                data_off = adaptation_field_length + 1;
            }
            size_t cpsz = sizeof(ts_pkt_data) - data_off;
            memcpy(w->au_nalus + w->au_o, pkts[o].data + data_off, cpsz);
            w->au_o += cpsz;
        }

        o++;
        if (pkts_fill == o) {
            o = 0;
            pkts_fill = fread(pkts, sizeof(ts_pkt), pkts_sz, f);
        }
    }

    // Flush a final frame
    if (reading_nals)
        write_au(w);
    flush_writer(w);

    return 0;
}

