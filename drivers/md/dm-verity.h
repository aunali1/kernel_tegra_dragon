/*
 * Copyright (C) 2010 The Chromium OS Authors <chromium-os-dev@chromium.org>
 *                    All Rights Reserved.
 * Copyright (C) 2012 Red Hat, Inc.
 * Copyright (C) 2015 Google, Inc.
 *
 * This file is released under the GPLv2.
 *
 * Provide error types for use when creating a custom error handler.
 * See Documentation/device-mapper/dm-verity.txt
 */

#ifndef DM_VERITY_H
#define DM_VERITY_H

#include "dm-bufio.h"
#include <linux/device-mapper.h>
#include <linux/notifier.h>
#include <crypto/hash.h>

#define DM_VERITY_MAX_LEVELS		63

enum verity_mode {
	DM_VERITY_MODE_EIO,
	DM_VERITY_MODE_LOGGING,
	DM_VERITY_MODE_RESTART
};

enum verity_block_type {
	DM_VERITY_BLOCK_TYPE_DATA,
	DM_VERITY_BLOCK_TYPE_METADATA
};

struct dm_verity {
        struct dm_dev *data_dev;
        struct dm_dev *hash_dev;
        struct dm_target *ti;
        struct dm_bufio_client *bufio;
        char *alg_name;
        struct crypto_shash *tfm;
        u8 *root_digest;        /* digest of the root block */
        u8 *salt;               /* salt: its size is salt_size */
        unsigned salt_size;
        sector_t data_start;    /* data offset in 512-byte sectors */
        sector_t hash_start;    /* hash start in blocks */
        sector_t data_blocks;   /* the number of data blocks */
        sector_t hash_blocks;   /* the number of hash blocks */
        unsigned char data_dev_block_bits;      /* log2(data blocksize) */
        unsigned char hash_dev_block_bits;      /* log2(hash blocksize) */
        unsigned char hash_per_block_bits;      /* log2(hashes in hash block) */
        unsigned char levels;   /* the number of tree levels */
        unsigned char version;
        unsigned digest_size;   /* digest size for the current hash algorithm */
        unsigned shash_descsize;/* the size of temporary space for crypto */
        int hash_failed;        /* set to 1 if hash of any block failed */
        enum verity_mode mode;  /* mode for handling verification errors */
        unsigned corrupted_errs;/* Number of errors for corrupted blocks */
        int error_behavior;     /* selects error behavior on io erros */

        struct workqueue_struct *verify_wq;

        /* starting blocks for each tree level. 0 is the lowest level. */
        sector_t hash_level_block[DM_VERITY_MAX_LEVELS];
};

struct dm_verity_io {
        struct dm_verity *v;

        /* original values of bio->bi_end_io and bio->bi_private */
        bio_end_io_t *orig_bi_end_io;
        void *orig_bi_private;

        sector_t block;
        unsigned n_blocks;

        struct bvec_iter iter;

        struct work_struct work;

        /*
         * Three variably-size fields follow this struct:
         *
         * u8 hash_desc[v->shash_descsize];
         * u8 real_digest[v->digest_size];
         * u8 want_digest[v->digest_size];
         *
         * To access them use: io_hash_desc(), io_real_digest() and io_want_digest().
         */
};

struct dm_verity_error_state {
	int code;
	int transient;  /* Likely to not happen after a reboot */
	u64 block;
	const char *message;

	sector_t dev_start;
	sector_t dev_len;
	struct block_device *dev;

	sector_t hash_dev_start;
	sector_t hash_dev_len;
	struct block_device *hash_dev;

	/* Final behavior after all notifications are completed. */
	int behavior;
};

/* This enum must be matched to allowed_error_behaviors in dm-verity.c */
enum dm_verity_error_behavior {
	DM_VERITY_ERROR_BEHAVIOR_EIO = 0,
	DM_VERITY_ERROR_BEHAVIOR_PANIC,
	DM_VERITY_ERROR_BEHAVIOR_NONE,
	DM_VERITY_ERROR_BEHAVIOR_NOTIFY
};

static inline struct shash_desc *verity_io_hash_desc(struct dm_verity *v,
						     struct dm_verity_io *io)
{
	return (struct shash_desc *)(io + 1);
}

static inline u8 *verity_io_real_digest(struct dm_verity *v,
					struct dm_verity_io *io)
{
	return (u8 *)(io + 1) + v->shash_descsize;
}

static inline u8 *verity_io_want_digest(struct dm_verity *v,
					struct dm_verity_io *io)
{
	return (u8 *)(io + 1) + v->shash_descsize + v->digest_size;
}

extern int verity_hash(struct dm_verity *v, struct shash_desc *desc,
		       const u8 *data, size_t len, u8 *digest);

extern int verity_hash_for_block(struct dm_verity *v, struct dm_verity_io *io,
				 sector_t block, u8 *digest);

int dm_verity_register_error_notifier(struct notifier_block *nb);
int dm_verity_unregister_error_notifier(struct notifier_block *nb);

#endif  /* DM_VERITY_H */
