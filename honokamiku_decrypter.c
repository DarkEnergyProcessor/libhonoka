/*!
 * \file honokamiku_decrypter.c
 * Routines implementation of HonokaMiku in ANSI C
 */

#include <stdlib.h>
#include <string.h>

#define HONOKAMIKU_DECRYPTER_CORE

#include "honokamiku_decrypter.h"
#include "honokamiku_key_tables.h"
#include "honokamiku_config.h"
#include "md5.h"

/*!
 * Version 2 key update macro.
 */
#define honokamiku_update_v2(dctx) \
	{ \
		unsigned int a, b, c, d; \
		a = (dctx)->update_key >> 16; \
		b = ((a * 1101463552) & 2147483647) + ((dctx)->update_key & 65535) * 16807; \
		c = (a * 16807) >> 15; \
		d = c + b - 2147483647; \
		b = b > 2147483646 ? d : b + c; \
		(dctx)->update_key = b; \
		(dctx)->xor_key = ((b >> 23) & 255) |((b >> 7) & 65280); \
	}

const char *hm_basename(const char *name)
{
	const char *pos = name + strlen(name);
	for(; *pos != '/' && *pos != '\\' && pos != name; pos--) {}

	if(pos != name) return pos + 1;
	else return name;
}

const char *honokamiku_version_string()
{
	return HONOKAMIKU_VERSION_STRING;
}

size_t honokamiku_version()
{
	/* libhonoka version: jjjmmmpppr */
	/* j - Major (not zero padded to prevent octal confusion)
	   m - Minor
	   p - Patch/Revision
	   r - Pre-release (1 - 8, 9 = not pre-release)
	 */
	return HONOKAMIKU_VERSION;
}

size_t honokamiku_context_size()
{
	return sizeof(honokamiku_context);
}

size_t honokamiku_header_size(honokamiku_decrypt_mode decrypt_mode)
{
	switch(decrypt_mode)
	{
		case honokamiku_decrypt_none:
		case honokamiku_decrypt_version1:
		default:
			return 0;
		case honokamiku_decrypt_version2:
			return 4;
		case honokamiku_decrypt_version3:
		case honokamiku_decrypt_version4:
		case honokamiku_decrypt_version5:
		case honokamiku_decrypt_version6:
			return 16;
	}
}

/*!
 * Initialize decrypter context. Used internally
 */
int honokamiku_dinit(
	honokamiku_context		*dctx,
	honokamiku_decrypt_mode	 decrypt_mode,
	const char				*prefix,
	const char				*filename,
	const void				*file_header
)
{
	/* The MD5 context */
	MD5_CTX mctx;
	/* Will contain the length of filename. */
	size_t filename_size;

	/* Zero memory */
	memset(dctx, 0, sizeof(honokamiku_context));
	
	/* Get basename */
	filename = hm_basename(filename);
	filename_size = strlen(filename);
	
	MD5Init(&mctx);
	MD5Update(&mctx, (unsigned char*)prefix, strlen(prefix));
	MD5Update(&mctx, (unsigned char*)filename, filename_size);
	MD5Final(&mctx);
	
	if (decrypt_mode == honokamiku_decrypt_none)
		/* Do nothing */
		return HONOKAMIKU_ERR_OK;
	if (decrypt_mode == honokamiku_decrypt_version1)
	{
		dctx->update_key = filename_size + 1;
		dctx->xor_key = dctx->init_key =
			(mctx.digest[0] << 24) |
			(mctx.digest[1] << 16) |
			(mctx.digest[2] << 8) |
			(mctx.digest[3]);
		dctx->pos = 0;
		dctx->dm = honokamiku_decrypt_version1;
		return HONOKAMIKU_ERR_OK;
	}
	if (decrypt_mode == honokamiku_decrypt_version2 ||
	    decrypt_mode == honokamiku_decrypt_auto
       )
	{
		/* Check if we can decrypt this */
		if (memcmp(mctx.digest + 4, file_header, 4) == 0)
		{
			/* Initialize decrypter context */
			dctx->dm = honokamiku_decrypt_version2;
			dctx->init_key = ((mctx.digest[0] & 127) << 24) |
										  (mctx.digest[1] << 16) |
										  (mctx.digest[2] << 8) |
										  mctx.digest[3];
			dctx->xor_key = ((dctx->init_key >> 23) & 255) |
										 ((dctx->init_key >> 7) & 65280);
			dctx->update_key = dctx->init_key;
			dctx->pos = 0;
			dctx->v3_initialized = 1;
			
			return HONOKAMIKU_ERR_OK;
		}
		else if (decrypt_mode == honokamiku_decrypt_version2)
			/* Cannot decrypt */
			return HONOKAMIKU_ERR_INVALIDMETHOD;
	}
	if (decrypt_mode >= honokamiku_decrypt_version3 ||
	    decrypt_mode == honokamiku_decrypt_auto
       )
	{
		/* Flipped file header */
		char actual_file_header[3];
		
		/* Flip file header bytes */
		actual_file_header[0] = ~mctx.digest[4];
		actual_file_header[1] = ~mctx.digest[5];
		actual_file_header[2] = ~mctx.digest[6];
		
		if (memcmp(actual_file_header, file_header, 3) == 0)
		{
			const char *foo = prefix;

			/* First-phase initialization */
			dctx->dm = decrypt_mode;
			dctx->pos = 0;
			dctx->v3_initialized = 0;
			dctx->init_key = ((mctx.digest[8] << 24) |
				(mctx.digest[9] << 16) |
				(mctx.digest[10] << 8) |
				mctx.digest[11]
			);
			dctx->second_init_key = ((mctx.digest[12] << 24) |
				(mctx.digest[13] << 16) |
				(mctx.digest[14] << 8) |
				mctx.digest[15]
			);

			/* Calculate automatic name sum */
			/* Store in first xor key */
			dctx->xor_key = 0;
			for(; *foo; dctx->xor_key += (unsigned char)*foo++);
			
			return HONOKAMIKU_ERR_OK;
		}
		else if (decrypt_mode != honokamiku_decrypt_auto)
			return HONOKAMIKU_ERR_INVALIDMETHOD;
	}
	
	/* No suitable decryption found */
	return HONOKAMIKU_ERR_DECRYPTUNKNOWN;
}

/*!
 * Initialize decrypter context for encryption. Used internally
 */
int honokamiku_einit(
	honokamiku_context      *dctx,
	honokamiku_decrypt_mode  decrypt_mode,
	const char              *prefix,
	const unsigned int      *key_tables,
	unsigned int             name_sum,
	const char              *filename,
	void                    *header_out,
	size_t                   header_size
)
{
	/* The MD5 context */
	MD5_CTX mctx;
	/* Variable used to read byte-per-byte from the header */
	char *header;
	/* The original filename size */
	size_t filename_size;

	/* For version 1, it doesn't matter if we're encrypting or decrypting */
	if(decrypt_mode == honokamiku_decrypt_version1)
		return honokamiku_dinit(dctx, decrypt_mode, prefix, filename, NULL);
	
	/* Zero memory decrypter context */
	memset(dctx, 0, sizeof(honokamiku_context));
	dctx->dm = decrypt_mode;
	
	header = (char*)header_out;
	
	/* Get basename */
	filename = hm_basename(filename);
	filename_size = strlen(filename);
	
	/* Compute MD5 */
	MD5Init(&mctx);
	MD5Update(&mctx, (unsigned char*)prefix, strlen(prefix));
	MD5Update(&mctx, (unsigned char*)filename, filename_size);
	MD5Final(&mctx);
	
	if (decrypt_mode == honokamiku_decrypt_none)
		/* Do nothing */
		return HONOKAMIKU_ERR_OK;
	else if (decrypt_mode == honokamiku_decrypt_version2)
	{
		if (header_size < 4) return HONOKAMIKU_ERR_BUFFERTOOSMALL;
		
		/* Initialize decrypter context */
		dctx->v3_initialized = 1;
		dctx->init_key = ((mctx.digest[0] & 127) << 24) |
						  (mctx.digest[1] << 16) |
						  (mctx.digest[2] << 8) |
						   mctx.digest[3];
		dctx->xor_key = ((dctx->init_key >> 23) & 255) |
									 ((dctx->init_key >> 7) & 65280);
		dctx->update_key = dctx->init_key;
		dctx->pos = 0;
		
		/* Copy header */
		memcpy(header_out, mctx.digest+4, 4);
		
		return HONOKAMIKU_ERR_OK;
	}
	else if (decrypt_mode >= honokamiku_decrypt_version3)
	{
		unsigned int filename_sum = name_sum;
		const char *loop_filename = filename;

		/* If header size is less than 16 bytes, then error */
		if (header_size < 16) return HONOKAMIKU_ERR_BUFFERTOOSMALL;
		
		/* Calculate filename binary char sum */
		for(; *loop_filename != 0; loop_filename++)
			filename_sum += (unsigned char)*loop_filename;

		/* Pre-initialize the initialization key in here */
		dctx->init_key = ((mctx.digest[8] << 24) |
			(mctx.digest[9] << 16) |
			(mctx.digest[10] << 8) |
			mctx.digest[11]
		);
		dctx->pos = 0;
		dctx->v3_initialized = 1;

		/* Clean up header */
		memset(header, 0, 16);
		
		switch(decrypt_mode)
		{
			case honokamiku_decrypt_version3:
			{
				/* Initialize decrypter context */
				dctx->add_val = 2531011;
				dctx->mul_val = 214013;
				dctx->shift_val = 24;
				dctx->xor_key = (
					dctx->update_key =
					dctx->init_key =
					key_tables[filename_sum & 63]
				);

				/* Write header */
				header[10] = filename_sum >> 8;
				header[11] = filename_sum & 255;
				break;
			}
			case honokamiku_decrypt_version4:
			{
				const lcg_keys* k = lcg_key_tables;
				
				/* Initialize decrypter context */
				dctx->add_val = k->increment;
				dctx->mul_val = k->multipler;
				dctx->shift_val = k->shift;
				dctx->xor_key = dctx->update_key = dctx->init_key;
				break;
			}
			case honokamiku_decrypt_version6:
			{
				/* Do secondary LCG initialization in here */
				/* Let V5 later do the primary LCG initialization */
				size_t i = 0;
				char selected_algo = 0;
				const char* fn2 = filename;
				const lcg_keys* select_lcg;

				/* Loop the basename */
				while(*fn2)
				{
					selected_algo += (((int)(-256)) | ~((int)(*fn2++)));
					i++;
				}

				/* Select the LCG keys */
				select_lcg = &lcg_key_tables[(i + selected_algo) & 3];
				
				/* Initialize secondary LCG values */
				dctx->second_add_val = select_lcg->increment;
				dctx->second_mul_val = select_lcg->multipler;
				dctx->second_shift_val = select_lcg->shift;

				/* Negate the init key here, so V5 will negate it again */
				dctx->init_key = ~dctx->init_key;
				dctx->second_xor_key = dctx->second_update_key =
				dctx->second_init_key = ((mctx.digest[12] << 24) |
					(mctx.digest[13] << 16) |
					(mctx.digest[14] << 8) |
					mctx.digest[15]
				);

				/* Keep going to V5 algorithm, thus no break */
			}
			case honokamiku_decrypt_version5:
			{
				/* Primary LCG initialization for V6 encryption */
				size_t i = 0;
				char selected_algo = 0;
				const char* fn2 = filename;
				const lcg_keys* select_lcg;

				/* Loop the basename */
				for(; *fn2; selected_algo += *fn2++, i++);

				select_lcg = &lcg_key_tables[(i + selected_algo) & 3];

				/* Initialize LCG key */
				dctx->add_val = select_lcg->increment;
				dctx->mul_val = select_lcg->multipler;
				dctx->shift_val = select_lcg->shift;
				
				/* Initialize key */
				dctx->xor_key =
				dctx->update_key =
				dctx->init_key = ~dctx->init_key;

				dctx->v5_encrypt = decrypt_mode == honokamiku_decrypt_version5;

				break;
			}
			default: return HONOKAMIKU_ERR_V3UNIMPLEMENTED;
		}
		
		/* Write header */
		header[0] = ~mctx.digest[4];
		header[1] = ~mctx.digest[5];
		header[2] = ~mctx.digest[6];
		header[3] = 12;
		header[7] = decrypt_mode == honokamiku_decrypt_version3 ? 0 :
			decrypt_mode - honokamiku_decrypt_version3 + 1;
		
		return HONOKAMIKU_ERR_OK;
	}

	return HONOKAMIKU_ERR_INVALIDMETHOD;
}

void honokamiku_decrypt_block(
	honokamiku_context  *dctx,
	void                *buffer,
	size_t               buffer_size
)
{
	char* file_buffer = (char*)buffer;
	
	if (buffer_size == 0) return; /* Do nothing */
	switch(dctx->dm)
	{
		case honokamiku_decrypt_none: return;
		case honokamiku_decrypt_version1:
		{
			unsigned int last_pos = dctx->pos & 3;
			size_t decrypt_size;

			if(last_pos == 1)
			{
				*file_buffer++ ^= dctx->xor_key >> 16;
				buffer_size--;

				if(buffer_size > 0)
					goto first_last_pos_mod2;
			}
			else if(last_pos == 2)
			{
				first_last_pos_mod2:

				*file_buffer++ ^= dctx->xor_key >> 8;
				buffer_size--;

				if(buffer_size > 0)
					goto first_last_pos_mod3;
			}
			else if(last_pos == 3)
			{
				first_last_pos_mod3:

				*file_buffer++ ^= dctx->xor_key;
				buffer_size--;

				dctx->xor_key += dctx->update_key;
			}

			for (decrypt_size = buffer_size >> 2; decrypt_size != 0; decrypt_size--, file_buffer += 4)
			{
				file_buffer[0] ^= dctx->xor_key >> 24;
				file_buffer[1] ^= dctx->xor_key >> 16;
				file_buffer[2] ^= dctx->xor_key >> 8;
				file_buffer[3] ^= dctx->xor_key;

				dctx->xor_key += dctx->update_key;
			}

			if ((buffer_size & 0xFFFFFFFCU) != buffer_size)
			{
				last_pos = buffer_size & 3;
			
				if(last_pos >= 1)
					file_buffer[0] ^= dctx->xor_key >> 24;
				if(last_pos >= 2)
					file_buffer[1] ^= dctx->xor_key >> 16;
				if(last_pos >= 3)
					file_buffer[2] ^= dctx->xor_key >> 8;
			}

			break;
		}
		case honokamiku_decrypt_version2:
		{
			size_t decrypt_size;
			
			/* Check if the last decrypt position is odd */
			if (dctx->pos & 1)
			{
				/* Then we'll decrypt single byte and update the key */
				file_buffer[0] ^= dctx->xor_key >> 8;
				file_buffer++;
				dctx->pos++;
				buffer_size--;
				
				honokamiku_update_v2(dctx);
			}
			
			/* Because we'll decrypt 2 bytes in every loop, divide by 2 */
			decrypt_size = buffer_size >> 1;
			
			for (; decrypt_size!=0; decrypt_size--, file_buffer+=2)
			{
				file_buffer[0] ^= dctx->xor_key;
				file_buffer[1] ^= dctx->xor_key >> 8;
				
				honokamiku_update_v2(dctx);
			}
			
			/* If it's odd, there should be 1 character need to decrypted. */
			/* In this case, we decrypt the last byte but don't update the key */
			if ((buffer_size & ((size_t)(-2))) != buffer_size)
				file_buffer[0] ^= dctx->xor_key;

			break;
		}
		case honokamiku_decrypt_version3:
		case honokamiku_decrypt_version4:
		{
			unsigned int i;
			size_t decrypt_size = buffer_size;

			for(
				i = dctx->xor_key;
				decrypt_size;
				i = (dctx->update_key = dctx->mul_val * dctx->update_key + dctx->add_val), decrypt_size--)
				*file_buffer++ ^= (i >> dctx->shift_val);

			dctx->xor_key = i;
			break;
		}
		case honokamiku_decrypt_version5:
		{
			/* AuahDark: I haven't inspected V5 encryption more */
			/* but caraxian said it works */
			size_t decrypt_size = buffer_size;
			char unknown = 89;

			if(dctx->v5_encrypt)
			{
				while(decrypt_size--)
				{
					unknown ^= (dctx->xor_key >> dctx->shift_val) ^ *file_buffer;
					*file_buffer++ = unknown;

					dctx->xor_key = (
						dctx->update_key =
							dctx->mul_val *
							dctx->update_key +
							dctx->add_val
					);
				}
			}
			else
			{
				while(decrypt_size--)
				{
					char temp = *file_buffer;
					*file_buffer++ ^= (dctx->xor_key >> dctx->shift_val) ^ unknown;
					unknown = temp;

					dctx->xor_key = (
						dctx->update_key =
							dctx->mul_val *
							dctx->update_key +
							dctx->add_val
					);
				}
			}
			break;
		}
		case honokamiku_decrypt_version6:
		{
			/* Update 2 LCG at same time :) */
			size_t decrypt_size = buffer_size;

			while(decrypt_size--)
			{
				*file_buffer++ ^= (
					(dctx->xor_key >> dctx->shift_val) ^
					(dctx->second_xor_key >> dctx->second_shift_val)
				);
				dctx->xor_key = (
					dctx->update_key =
						dctx->mul_val *
						dctx->update_key +
						dctx->add_val
				);
				dctx->second_xor_key = (
					dctx->second_update_key =
						dctx->second_mul_val *
						dctx->second_update_key +
						dctx->second_add_val
				);
			}
			break;
		}
		default: break;
	}
	
	dctx->pos += buffer_size;
}

int honokamiku_jump_offset(
	honokamiku_context *dctx,
	unsigned int        offset
)
{
	int reset_dctx;
	unsigned int loop_times;
	honokamiku_decrypt_mode decrypt_mode;
	
	reset_dctx = 0;
	decrypt_mode = dctx->dm;

	/* Check if the current context is V5 because */
	/* seeking is not supported in V5 */
	if (decrypt_mode == honokamiku_decrypt_version5)
		return HONOKAMIKU_ERR_UNIMPLEMENTED;
	
	/* Check if we're seeking forward */
	if (offset > dctx->pos)
		loop_times = offset - dctx->pos;
	else if (offset == dctx->pos)
		/* Do nothing if the offset = pos*/
		return HONOKAMIKU_ERR_OK;
	else
	{
		/* Seeking backward */
		loop_times = offset;
		reset_dctx = 1;
	}

	if (decrypt_mode == honokamiku_decrypt_none) {}
	else if (decrypt_mode == honokamiku_decrypt_version1)
	{
		unsigned int c, n;
		size_t i;
		c = dctx->pos - (dctx->pos & 3);
		n = offset - (offset & 3);

		if(c > n)
			/* subtract */
			for(i = (c - n)>>2; i > 0; dctx->xor_key -= dctx->update_key, i--);
		else if(n > c)
			/* addition */
			for(i = (c - n)>>2; i > 0; dctx->xor_key += dctx->update_key, i--);
	}
	else if (decrypt_mode == honokamiku_decrypt_version2)
	{
		if (reset_dctx)
		{
			dctx->update_key = dctx->init_key;
			dctx->xor_key = ((dctx->init_key >> 23) & 255) |
							((dctx->init_key >> 7) & 65280);
		}
		
		if (dctx->pos % 2 == 1 && reset_dctx == 0)
		{
			loop_times--;
			honokamiku_update_v2(dctx);
		}
		
		loop_times /= 2;
		
		for(; loop_times != 0; loop_times--)
			honokamiku_update_v2(dctx);
	}
	else if (
		decrypt_mode == honokamiku_decrypt_version3 ||
		decrypt_mode == honokamiku_decrypt_version4
	)
	{
		/* V3 and V4 actually shares same jump method if we treat V3 as V4 */
		/* which uses 2nd LCG keys (MSVC LCG parameters) */
		if (reset_dctx)
			dctx->xor_key = dctx->update_key = dctx->init_key;
		
		for(; loop_times != 0; loop_times--)
			dctx->xor_key = (
				dctx->update_key =
					dctx->update_key *
					dctx->mul_val +
					dctx->add_val
			);
	}
	else if (decrypt_mode == honokamiku_decrypt_version6)
	{
		/* There are 2 LCG which needs to be updated here */
		if (reset_dctx)
		{
			dctx->xor_key = dctx->update_key = dctx->init_key;
			dctx->second_xor_key =
			dctx->second_update_key =
			dctx->second_init_key;
		}
		
		for(; loop_times != 0; loop_times--)
		{
			dctx->xor_key = (
				dctx->update_key =
					dctx->update_key *
					dctx->mul_val +
					dctx->add_val
			);
			dctx->second_xor_key = (
				dctx->second_update_key =
					dctx->second_update_key *
					dctx->second_mul_val +
					dctx->second_add_val
			);
		}
	}
	
	dctx->pos = offset;
	return HONOKAMIKU_ERR_OK;
}

int honokamiku_decrypt_init(
	honokamiku_context      *dctx,
	honokamiku_decrypt_mode  decrypt_mode,
	honokamiku_gamefile_id   gid,
	const char              *gpf,
	const char              *filename,
	const void              *file_header
)
{
	if (
		(gid != honokamiku_gamefile_unknown && gpf != NULL) ||
		(gid == honokamiku_gamefile_unknown && gpf == NULL)
	)
		/* Only one of them can be zero/NULL */
		return HONOKAMIKU_ERR_INVALIDARG;

	if (gpf == NULL)
	{
		switch (gid)
		{
			case honokamiku_gamefile_en:
				gpf = HONOKAMIKU_KEY_SIF_EN;
				break;
			case honokamiku_gamefile_jp:
				gpf = HONOKAMIKU_KEY_SIF_JP;
				break;
			case honokamiku_gamefile_tw:
				gpf = HONOKAMIKU_KEY_SIF_TW;
				break;
			case honokamiku_gamefile_cn:
				gpf = HONOKAMIKU_KEY_SIF_CN;
				break;
			default:
				return HONOKAMIKU_ERR_INVALIDARG;
		}
	}
	
	return honokamiku_dinit(dctx, decrypt_mode, gpf, filename, file_header);
}

honokamiku_gamefile_id honokamiku_decrypt_init_auto(
	honokamiku_context	*dctx,
	const char			*filename,
	const void			*file_header
)
{
	honokamiku_gamefile_id gid;
	
	/* Loop through all known game IDs*/
	for (gid = honokamiku_gamefile_en; gid <= honokamiku_gamefile_cn; gid++)
	{
		if (honokamiku_decrypt_init(dctx, honokamiku_decrypt_auto, gid, NULL, filename, file_header) == HONOKAMIKU_ERR_OK)
			return gid;
	}
	return honokamiku_gamefile_unknown;
}

int honokamiku_decrypt_final_init(
	honokamiku_context     *dctx,
	honokamiku_gamefile_id  gid,
	const unsigned int     *key_tables,
	int                     name_sum,
	const char             *filename,
	const void             *next_header
)
{
	honokamiku_decrypt_mode dmode_file;
	const char *header = (const char*)next_header;
	int flip_init_v3 = 0;

	/* We validate the arguments */
	if (gid == honokamiku_gamefile_unknown)
	{
		if (key_tables == NULL)
			return HONOKAMIKU_ERR_INVALIDARG;
	}
	else
	{
		int actual_name_sum = 0;

		switch(gid)
		{
			case honokamiku_gamefile_en:
				actual_name_sum = 844;
				key_tables = en_v3_keytables;
				break;
			case honokamiku_gamefile_jp:
				actual_name_sum = 500;
				key_tables = jp_v3_keytables;
				break;
			case honokamiku_gamefile_tw:
				actual_name_sum = 1051;
				key_tables = tw_v3_keytables;
				break;
			case honokamiku_gamefile_cn:
				actual_name_sum = 1847;
				key_tables = cn_v3_keytables;
				break;
			default:
				return HONOKAMIKU_ERR_INVALIDARG;
		}

		if (name_sum != (-1))
			name_sum = actual_name_sum;
	}

	if (name_sum == (-1))
		name_sum = dctx->xor_key;

	if (
		(dctx->dm > (-1) && dctx->dm < honokamiku_decrypt_version3) ||
		dctx->v3_initialized
	)
		/* Nothing to post-initialize */
		return HONOKAMIKU_ERR_OK;

	/* Check the header for encryption method */
	switch(header[3])
	{
		case 1: flip_init_v3 = 1;
		case 0: dmode_file = honokamiku_decrypt_version3; break;
		case 2: dmode_file = honokamiku_decrypt_version4; break;
		case 3: dmode_file = honokamiku_decrypt_version5; break;
		case 4: dmode_file = honokamiku_decrypt_version6; break;
		case 5: return HONOKAMIKU_ERR_V3UNIMPLEMENTED;
		default: return HONOKAMIKU_ERR_DECRYPTUNKNOWN;
	}

	if (dctx->dm == honokamiku_decrypt_auto)
		dctx->dm = dmode_file;
	else if (dctx->dm != dmode_file)
		return HONOKAMIKU_ERR_INVALIDMETHOD;

	if (dmode_file == honokamiku_decrypt_version3)
	{
		/* Calculate name sum */
		const char *basename = hm_basename(filename);
		unsigned int file_name_sum = (unsigned char)header[7] | (unsigned char)header[6] << 8;
		unsigned int name_sum_idx = file_name_sum & 63;

		/* Compute the name sum at the same time */
		for(; *basename; file_name_sum -= *basename++);

#ifndef HONOKAMIKU_V3_NOHDR_CHECK
		if (file_name_sum == name_sum)
		{
#endif
			if (flip_init_v3) dctx->init_key = ~key_tables[name_sum_idx];
			else dctx->init_key = key_tables[name_sum_idx];

			dctx->xor_key = dctx->update_key = dctx->init_key;
			dctx->add_val = 2531011;
			dctx->mul_val = 214013;
			dctx->shift_val = 24;
			dctx->v3_initialized = 1;

			return HONOKAMIKU_ERR_OK;
#ifndef HONOKAMIKU_V3_NOHDR_CHECK
		}

		return HONOKAMIKU_ERR_DECRYPTUNKNOWN;
#endif
	}
	else if (dmode_file == honokamiku_decrypt_version4)
	{
		const lcg_keys *keys = &lcg_key_tables[(size_t)header[2]];

		dctx->xor_key = dctx->update_key = dctx->init_key;
		dctx->add_val = keys->increment;
		dctx->mul_val = keys->multipler;
		dctx->shift_val = keys->shift;
		dctx->v3_initialized = 1;

		return HONOKAMIKU_ERR_OK;
	}
	else if (dmode_file == honokamiku_decrypt_version5)
	{
		/* We have to compute the LCG index we'll use */
		const lcg_keys *keys;
		char select_lcg = 0;
		size_t i = 0;
		const char *basename = hm_basename(filename);

		for(; *basename; i++, select_lcg += *basename++);

		keys = &lcg_key_tables[(i + select_lcg) & 3];

		dctx->init_key = ~dctx->init_key;
		dctx->xor_key = dctx->update_key = dctx->init_key;
		dctx->add_val = keys->increment;
		dctx->mul_val = keys->multipler;
		dctx->shift_val = keys->shift;
		dctx->v3_initialized = 1;

		return HONOKAMIKU_ERR_OK;
	}
	else if (dmode_file == honokamiku_decrypt_version6)
	{
		/* In V6, 2 LCG initialization is done */
		const lcg_keys *keys1;
		const lcg_keys *keys2;
		char select_lcg = 0;
		char select_lcg2 = 0;
		size_t i = 0;
		const char *basename = hm_basename(filename);
		
		for(;
			*basename;
			i++,
			select_lcg += *basename,
			select_lcg2 += ((int)(-256)) | ~((int)(*basename++))
		);

		keys1 = &lcg_key_tables[(i + select_lcg) & 3];
		keys2 = &lcg_key_tables[(i + select_lcg2) & 3];
		
		dctx->xor_key = dctx->update_key = dctx->init_key;
		dctx->add_val = keys1->increment;
		dctx->mul_val = keys1->multipler;
		dctx->shift_val = keys1->shift;
		dctx->second_xor_key = dctx->second_update_key = dctx->second_init_key;
		dctx->second_add_val = keys2->increment;
		dctx->second_mul_val = keys2->multipler;
		dctx->second_shift_val = keys2->shift;
		dctx->v3_initialized = 1;

		return HONOKAMIKU_ERR_OK;
	}

	/* Should not be reached */
	return HONOKAMIKU_ERR_DECRYPTUNKNOWN;
}

int honokamiku_decrypt_is_final_init(honokamiku_context *dctx)
{
	return (
		(
			dctx->dm == honokamiku_decrypt_auto ||
			dctx->dm >= honokamiku_decrypt_version3
		) && !dctx->v3_initialized
	);
}

int honokamiku_encrypt_init(
	honokamiku_context      *dctx,
	honokamiku_decrypt_mode  decrypt_mode,
	honokamiku_gamefile_id   gid,
	const char              *gpf,
	const unsigned int      *key_tables,
	int                      name_sum,
	const char              *filename,
	void                    *header_out,
	size_t                   header_size
)
{

	if (gid == honokamiku_gamefile_unknown)
	{
		if (key_tables == NULL || gpf == NULL)
			/* Prefix and key tables must be specificed */
			return HONOKAMIKU_ERR_INVALIDARG;
	}
	else
	{
		int actual_name_sum = 0;

		switch(gid)
		{
			case honokamiku_gamefile_en:
				actual_name_sum = 844;
				key_tables = en_v3_keytables;
				gpf = HONOKAMIKU_KEY_SIF_EN;
				break;
			case honokamiku_gamefile_jp:
				actual_name_sum = 500;
				key_tables = jp_v3_keytables;
				gpf = HONOKAMIKU_KEY_SIF_JP;
				break;
			case honokamiku_gamefile_tw:
				actual_name_sum = 1051;
				key_tables = tw_v3_keytables;
				gpf = HONOKAMIKU_KEY_SIF_TW;
				break;
			case honokamiku_gamefile_cn:
				actual_name_sum = 1847;
				key_tables = cn_v3_keytables;
				gpf = HONOKAMIKU_KEY_SIF_CN;
				break;
			default:
				return HONOKAMIKU_ERR_INVALIDARG;
		}

		if (name_sum != (-1))
			name_sum = actual_name_sum;
	}

	if (name_sum == (-1))
	{
		/* Calculate name sum */
		const char *foo;
		name_sum = 0;

		for(foo = gpf; *foo; name_sum += (unsigned char)*foo++);
	}

	return honokamiku_einit(
		dctx,
		decrypt_mode,
		gpf,
		key_tables,
		name_sum,
		filename,
		header_out,
		header_size
	);
}
