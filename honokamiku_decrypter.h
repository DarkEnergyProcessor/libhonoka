/*!
 * \file honokamiku_decrypter.h
 * Header of HonokaMiku ANSI C implementation
 */

#ifndef __DEP_HONOKAMIKU_H
#define __DEP_HONOKAMIKU_H

#if defined(_WIN32) || defined(WIN32)
#	define _HMEXP __declspec(dllexport)
#	define _HMIMP __declspec(dllimport)
#elif defined(__GNUC__)
#	define _HMEXP __attribute__ ((visibility ("default")))
#	define _HMIMP
#else
#	define _HMEXP
#	define _HMIMP
#endif

#if defined(HONOKAMIKU_SHARED)
#	if defined(HONOKAMIKU_DECRYPTER_CORE)
#		define HMAPI _HMEXP
#	else
#		define HMAPI _HMIMP
#	endif
#else
#	define HMAPI extern
#endif

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#include <stdlib.h>

/******************************************************************************
** Error codes                                                               **
******************************************************************************/
#define HONOKAMIKU_ERR_OK              0 /*!< No error (success) */
#define HONOKAMIKU_ERR_DECRYPTUNKNOWN  1 /*!< No method found to decrypt this
                                              file */
#define HONOKAMIKU_ERR_BUFFERTOOSMALL  2 /*!< Buffer to store the headers is
                                              too small */
#define HONOKAMIKU_ERR_INVALIDMETHOD   3 /*!< Invalid decryption method */
#define HONOKAMIKU_ERR_V3UNIMPLEMENTED 4 /*!< Unimplemented V3+ decryption
                                              method */
#define HONOKAMIKU_ERR_INVALIDARG      5 /*!< Invalid argument */
#define HONOKAMIKU_ERR_UNIMPLEMENTED   6 /*!< Method unimplemented */

/******************************************************************************
** Pre-defined prefix for game files                                         **
******************************************************************************/
#define HONOKAMIKU_KEY_SIF_EN    "BFd3EnkcKa"
#define HONOKAMIKU_KEY_SIF_WW    "BFd3EnkcKa"
#define HONOKAMIKU_KEY_SIF_JP    "Hello"
#define HONOKAMIKU_KEY_SIF_TW    "M2o2B7i3M6o6N88"
#define HONOKAMIKU_KEY_SIF_CN    "iLbs0LpvJrXm3zjdhAr4"

/*!
 * Decryption modes.
 */
typedef enum honokamiku_decrypt_mode
{
	honokamiku_decrypt_none,       /*!< Transparent encryption/decryption. */
	honokamiku_decrypt_version1,   /*!< Version 1 encryption/decryption.
                                        TODO: Implementation */
	honokamiku_decrypt_version2,   /*!< Version 2 encryption/decryption */
	honokamiku_decrypt_version3,   /*!< Version 3 encryption/decryption */
	honokamiku_decrypt_version4,   /*!< Version 4 encryption/decryption */
	honokamiku_decrypt_version5,   /*!< Version 5 encryption/decryption */
	honokamiku_decrypt_version6,   /*!< Version 6 encryption/decryption */
	
	honokamiku_decrypt_auto = (-1) /*!< Automatically determine decryption type
                                        from honokamiku_decrypt_init() */
} honokamiku_decrypt_mode;

/*!
 * Game file IDs for HonokaMiku.
 */
typedef enum
{
	honokamiku_gamefile_unknown, /*!< Unknown game file */
	honokamiku_gamefile_en,      /*!< SIF EN game file */
	honokamiku_gamefile_jp,      /*!< SIF JP game file */
	honokamiku_gamefile_tw,      /*!< SIF TW game file */
	honokamiku_gamefile_cn,      /*!< SIF CN game file */
	
	honokamiku_gamefile_ww = honokamiku_gamefile_en /*!< SIF EN game file */
} honokamiku_gamefile_id;

/*!
 * Decrypter context structure. All honokamiku_* functions need this structure.
 */
typedef struct honokamiku_context
{
	honokamiku_decrypt_mode dm;    /*!< Decryption version */
	unsigned int init_key;         /*!< Key used at pos 0. Used when the
                                        decrypter needs to jump to
                                        specific-position */
	unsigned int update_key;       /*!< Current key at `pos` */
	unsigned int xor_key;          /*!< Values to use when XOR-ing bytes */
	unsigned int pos;              /*!< Variable to track current position.
                                        Needed to allow jump to
                                        specific-position */
	unsigned int shift_val;        /*!< Version 3+: LCG shift value
                                        (not modulus) */
	unsigned int mul_val;          /*!< Version 3+: LCG multiply value */
	unsigned int add_val;          /*!< Version 3+: LCG increment value */
	unsigned int second_init_key;  /*!< Version 6+: Secondary initialization
                                        key. Same as `init_key` */
	unsigned int second_update_key;/*!< Version 6+: Secondary update key. Same
                                        as `update_key` */
	unsigned int second_xor_key;   /*!< Version 6+: Secondary value used when
                                        XOR-ing bytes. Same as `xor_key` */
	unsigned int second_shift_val; /*!< Version 6+: Secondary LCG shift value*/
	unsigned int second_mul_val;   /*!< Version 6+: Secondary LCG multiply
                                        value */
	unsigned int second_add_val;   /*!< Version 6+: Secondary LCG increment
                                        value */
	char         v3_initialized;   /*!< Is the decrypter context is fully
                                        initialized? */
	char         v5_encrypt;       /*!< Does we're encrypting in V5 instead?
                                        V5 has different algorithm for
                                        encryption and decryption. */
} honokamiku_context;

/******************************************************************************
** Functions                                                                 **
******************************************************************************/

/*!
 * Returns libhonoka version as string. Useful for display.
 */
HMAPI const char *honokamiku_version_string();

/*!
 * Returns libhonoka version as integer. Useful for comparison.
 */
HMAPI size_t honokamiku_version();

/*!
 * Returns honokamiku_context size, in bytes. Useful to preserve forward
 * compatibility when the context structure is changed
 */
HMAPI size_t honokamiku_context_size();

/*!
 * \brief Get header size of specificed decrypt mode
 * \param decrypt_mode The decryption mode/algorithm/version
 * \returns Size of the header
 */
HMAPI size_t honokamiku_header_size(honokamiku_decrypt_mode decrypt_mode);

/*!
 * \brief Initialize HonokaMiku decrypter context to decrypt a file.
 * \param decrypter_context HonokaMiku decrypter context to be initialized
 * \param decrypt_mode HonokaMiku decryption mode.
 * \param gamefile_id Game file to decrypt. This can be
 *                    ::honokamiku_gamefile_unknown if \a gamefile_prefix is
 *                    not NULL
 * \param gamefile_prefix Unique string used when initializing the
 *                        \a decrypter_context. This can be NULL if
 *                        \a gamefile_id is not ::honokamiku_gamefile_unknown
 * \param filename File name that want to be decrypted.
 * \param file_header The first 4-bytes contents of the file
 * \returns One of HONOKAMIKU_ERR_* defines. #HONOKAMIKU_ERR_OK on success.
 * \warning You can't set \a gamefile_id to values other than
 *          ::honokamiku_gamefile_unknown if \a gamefile_prefix is not NULL.  
 *          You also can't set \a gamefile_prefix to NULL if \a gamefile_id
 *          is ::honokamiku_gamefile_unknown. In short: Only one of them can be
 *          zero/NULL.
 * \todo Version 1 decrypter initialization
 * \sa honokamiku_context
 * \sa honokamiku_decrypt_mode
 * \sa honokamiku_gamefile_id
 */ 
HMAPI int honokamiku_decrypt_init(
	honokamiku_context      *decrypter_context,
	honokamiku_decrypt_mode  decrypt_mode,
	honokamiku_gamefile_id   gamefile_id,
	const char              *gamefile_prefix,
	const char              *filename,
	const void              *file_header
);

/*!
 * \brief Initialize HonokaMiku decrypter context with all possible known game
 *        ID.
 * \param decrypter_context HonokaMiku decrypter context to be initialized
 * \param filename File name that want to be decrypted
 * \param file_header The first 4-bytes contents of the file
 * \returns One of honokamiku_gamefile_id values. ::honokamiku_gamefile_unknown
 *          if no suitable decryption method is found.
 * \sa honokamiku_decrypt_init()
 * \sa honokamiku_context
 * \sa honokamiku_gamefile_id
 */
HMAPI honokamiku_gamefile_id honokamiku_decrypt_init_auto(
	honokamiku_context *decrypter_context,
	const char         *filename,
	const void         *file_header
);

/*!
 * \brief Second-phase decrypter context initialization
 * \param decrypter_context HonokaMiku decrypter context
 * \param gamefile_id Game file to decrypt. This can be
 *                    ::honokamiku_gamefile_unknown if custom key tables and
 *                    name sum is used.
 * \param key_tables Version 3 key tables. Can be NULL if decrypter context
 *                   is known SIF game file.
 * \param name_sum Version 3 name sum. Can be -1 if decrypter context is known
 *                 SIF game file.
 * \param filename File name that want to be decrypted
 * \param next_header Next 12-bytes contents of the file
 * \returns One of HONOKAMIKU_ERR_* defines. #HONOKAMIKU_ERR_OK on success.
 *          Also returns #HONOKAMIKU_ERR_OK if specificed decrypter context
 *          is not version 3 (or later) decryption method.
 * \note To check whenever decrypter context needs to be second-phase
 *       initialized, call honokamiku_decrypt_is_final_init()
 */
HMAPI int honokamiku_decrypt_final_init(
	honokamiku_context     *decrypter_context,
	honokamiku_gamefile_id  gamefile_id,
	const unsigned int     *key_tables,
	int                     name_sum,
	const char             *filename,
	const void             *next_header
);

/*!
 * \brief Check whenever decrypter context needs to be second-phase initialized
 * \param decrypter_context HonokaMiku decrypter context to check
 * \returns 0 if second-phase initialization not needed. 1 otherwise
 * \note If second-phase initialization is needed, read the next 12-bytes of
 *       the file and supply it to honokamiku_decrypt_final_init()
 */
HMAPI int honokamiku_decrypt_is_final_init(
	honokamiku_context *decrypter_context
);

/*!
 * \brief Initialize HonokaMiku decrypter context to encrypt a file.
 * \param decrypter_context HonokaMiku decrypter context to be initialized
 * \param decrypt_mode HonokaMiku encryption mode
 * \param gamefile_id Game file to encrypt
 * \param gamefile_prefix Unique string used when initializing the
 *                        \a decrypter_context
 * \param key_tables Version 3 key tables. Can be NULL if decrypter context is
 *                   known SIF game file.
 * \param name_sum Version 3 name sum. Can be -1 if decrypter context is known
 *                 SIF game file.
 * \param filename File name that want to be encrypted
 * \param header_out Pointer to store the file headers
 * \param header_size Size of \a header_out
 * \returns One of HONOKAMIKU_ERR_* defines. #HONOKAMIKU_ERR_OK on success.
 * \todo Version 1 encryption initialization
 * \sa honokamiku_decrypt_init()
 * \sa honokamiku_context
 * \sa honokamiku_decrypt_mode
 */
HMAPI int honokamiku_encrypt_init(
	honokamiku_context      *decrypter_context,
	honokamiku_decrypt_mode  decrypt_mode,
	honokamiku_gamefile_id   gamefile_id,
	const char              *gamefile_prefix,
	const unsigned int      *key_tables,
	int                      name_sum,
	const char              *filename,
	void                    *header_out,
	size_t                   header_size
);

/*!
 * \brief XOR block of memory with specificed decrypt mode and decrypter
 *        context.
 * \param decrypter_context HonokaMiku decrypter context that already
 *                          initialized with honokamiku_decrypt_init()
 * \param buffer Buffer to be decrypted
 * \param buffer_size Size of `buffer`
 * \todo Version 1 decryption routines
 * \sa honokamiku_decrypt_init()
 * \sa honokamiku_context
 * \sa honokamiku_decrypt_mode
 */
HMAPI void honokamiku_decrypt_block(
	honokamiku_context *decrypter_context,
	void               *buffer,
	size_t              buffer_size
);

/*!
 * \brief Recalculate decrypter context to decrypt at specific position.
 * \param decrypter_context HonokaMiku decrypter context to set it's position
 * \param offset Absolute position (starts at 0)
 * \returns #HONOKAMIKU_ERR_OK on success, #HONOKAMIKU_ERR_UNIMPLEMENTED if
 *          decrypter context doesn't support seeking
 * \todo Version 1 decryption jump
 * \sa honokamiku_context
 * \sa honokamiku_decrypt_init()
 * \sa honokamiku_decrypt_mode
 */
HMAPI int honokamiku_jump_offset(
	honokamiku_context *decrypter_context,
	unsigned int        offset
);

/******************************************************************************
** Useful macros                                                             **
******************************************************************************/
/*!
 * \brief Initialize decrypter context to decrypt SIF EN game file.
 * \param decrypter_context HonokaMiku decrypter context to be initialized
 * \param filename File name that want to be decrypted.
 * \param file_header The first 4-bytes contents of the file
 * \sa honokamiku_decrypt_init
 */
#define honokamiku_decrypt_init_sif_en(decrypter_context,filename,file_header) \
	honokamiku_decrypt_init( \
	    decrypter_context, \
	    honokamiku_decrypt_auto, \
	    honokamiku_gamefile_unknown, \
	    HONOKAMIKU_KEY_SIF_EN, \
	    filename, \
	    file_header)

/*!
 * \brief Initialize decrypter context to decrypt SIF JP game file.
 * \param decrypter_context HonokaMiku decrypter context to be initialized
 * \param filename File name that want to be decrypted.
 * \param file_header The first 4-bytes contents of the file
 * \sa honokamiku_decrypt_init
 */
#define honokamiku_decrypt_init_sif_jp(decrypter_context,filename,file_header) \
	honokamiku_decrypt_init( \
	    decrypter_context, \
	    honokamiku_decrypt_auto, \
	    honokamiku_gamefile_unknown, \
	    HONOKAMIKU_KEY_SIF_JP, \
	    filename, \
	    file_header)

/*!
 * \brief Initialize decrypter context to decrypt SIF TW game file.
 * \param decrypter_context HonokaMiku decrypter context to be initialized
 * \param filename File name that want to be decrypted.
 * \param file_header The first 4-bytes contents of the file
 * \sa honokamiku_decrypt_init
 */
#define honokamiku_decrypt_init_sif_tw(decrypter_context,filename,file_header) \
	honokamiku_decrypt_init( \
	    decrypter_context, \
	    honokamiku_decrypt_auto, \
	    honokamiku_gamefile_unknown, \
	    HONOKAMIKU_KEY_SIF_TW, \
	    filename, \
	    file_header)

/*!
 * \brief Initialize decrypter context to decrypt SIF CN game file.
 * \param decrypter_context HonokaMiku decrypter context to be initialized
 * \param filename File name that want to be decrypted.
 * \param file_header The first 4-bytes contents of the file
 * \sa honokamiku_decrypt_init
 */
#define honokamiku_decrypt_init_sif_cn(decrypter_context,filename,file_header) \
	honokamiku_decrypt_init( \
	    decrypter_context, \
	    honokamiku_decrypt_auto, \
	    honokamiku_gamefile_unknown, \
	    HONOKAMIKU_KEY_SIF_CN, \
	    filename, \
	    file_header)

#ifdef __cplusplus
}
#endif /* __cplusplus */
#endif /* __DEP_HONOKAMIKU_H */
