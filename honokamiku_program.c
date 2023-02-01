/*!
 * \file honokamiku_program.c
 * The program executable
 */

#include <errno.h>
#include <memory.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#ifdef _WIN32
#include <io.h>
#include <fcntl.h>
#endif

#define HONOKAMIKU_DECRYPTER_CORE
#include "honokamiku_decrypter.h"

/*!
 * Used to map letter to gamefile id
 */
int map_letter_to_gamefile(const char *letter, honokamiku_gamefile_id *gid, honokamiku_decrypt_mode *dmode)
{
	honokamiku_decrypt_mode ver = honokamiku_decrypt_version3;

	if (letter[1] >= '1' && letter[1] <= '6')
	{
		switch (letter[1])
		{
			case '1': ver = honokamiku_decrypt_version1; break;
			case '2': ver = honokamiku_decrypt_version2; break;
			case '3': ver = honokamiku_decrypt_version3; break;
			case '4': ver = honokamiku_decrypt_version4; break;
			case '5': ver = honokamiku_decrypt_version5; break;
			case '6': ver = honokamiku_decrypt_version6; break;
			default: break;
		}
	}

	switch (*letter)
	{
		case 'W':
		case 'w':
			*gid = honokamiku_gamefile_en;
			break;
		case 'J':
		case 'j':
			*gid = honokamiku_gamefile_jp;
			break;
		case 'T':
		case 't':
			*gid = honokamiku_gamefile_tw;
			break;
		case 'C':
		case 'c':
			*gid = honokamiku_gamefile_cn;
			break;
		case 'x':
		case 'X':
			*gid = honokamiku_gamefile_unknown;
			break;
		default:
			*gid = honokamiku_gamefile_unknown;
			*dmode = honokamiku_decrypt_none;
			return 0;
	}

	*dmode = ver;
	return 1;
}

/*!
 * Inverse of map_letter_to_gamefile()
 */
const char* gamefile_to_string(honokamiku_gamefile_id id)
{
	switch(id)
	{
		case honokamiku_gamefile_en:
			return "SIF WW";
		case honokamiku_gamefile_jp:
			return "SIF JP";
		case honokamiku_gamefile_tw:
			return "SIF TW";
		case honokamiku_gamefile_cn:
			return "SIF CN";
		default:
			return "Unknown";
	}
}

/*!
 * Usage information
 */
void show_usage(const char* name)
{
	const char* original_name = name;
	
	name += strlen(name);
	for (; *name != '/' && *name != '\\' && name >= original_name; name--);
	name++;
	
	fprintf(stderr, "Usage: %s [options] <input file> [options] [output file=input file] [options]\n\n"
					"output file can be - for stdout (input file must support seeking)\n\n"
					"Options:\r\n"
					"-b <name>        <name> is the actual filename for <input file>.\n"
					"                 This is useful if you're decrypting/encrypting with\n"
					"                 different filename.\n"
					"-c               Decrypt/encrypt SIF CN game file.\n"
					"-d               Detect encryption type only.\n"
					"-e               Encrypt <input file> to specificed game file.\n", name);
	fputs(			"-h, -?           Show help (this message).\n"
					"-j               Decrypt/encrypt SIF JP game file.\n"
					"-k <file>        File which contains keytable for custom game file.\n"
					"-l               Show license.\n"
					"                 Warning: bunch of text!\n"
					"-p <string>      Specify the prefix for custom game file.\n"
					"-s <number>      Specify the version 3 name sum for custom game file.\n"
					"-t               Decrypt/encrypt SIF TW game file.\n"
					"-v               Show version information.\n", stderr);
	fputs(			"-w               Decrypt/encrypt SIF EN game file.\n"
					"-x               Decrypt/encrypt custom game file.\n"
					"Letter (for -e):\n"
					"w = SIF EN; j = SIF JP; t = SIF TW; k = SIF KR; c = SIF CN\n\n", stderr);
}

/*!
 * The main entry point
 */
int main(int argc, char *argv[])
{
	static const size_t BUFFER_SIZE = 4096;

	honokamiku_context *dctx;
	FILE *file;
	const char *basename;
	const char *file_input;
	const char *file_output;
	const char *default_prefix = NULL;
	char *file_buffer;
	unsigned int custom_ktbl[65];
	unsigned int *select_ktbl = NULL;
	honokamiku_gamefile_id expected_id;
	honokamiku_decrypt_mode expected_mode;
	size_t header_size = 0;
	size_t file_contents_length = 0;
	size_t file_contents_size = BUFFER_SIZE;
	char file_header[16];
	int is_stdin = 0, is_custom = 0;
	int def_name_sum = (-1);
	int input_arg;
	int output_arg;
	char test_mode;
	char encrypt_mode;
	int i;
	
	/* Initialize values */
	dctx = (honokamiku_context*)calloc(1, honokamiku_context_size());
	file = NULL;
	basename = file_input = file_output = NULL;
	expected_id = honokamiku_gamefile_unknown;
	expected_mode = honokamiku_decrypt_none;
	input_arg = output_arg = 0;
	test_mode = encrypt_mode = 0;
	custom_ktbl[64] = 0;
	
	/* Set stdout to binary mode for Windows*/
#ifdef _WIN32
	_setmode(0, O_BINARY);
	_setmode(1, O_BINARY); /* stdout = 1 */
#endif
	
	/* Check argc */
	if (argc < 2)
	{
		/* Show usage */
		show_usage(argv[0]);
		return 1;
	}
	
	/* Parse arguments */
	for (i = 1; i < argc; i++)
	{
		size_t arg_str_len;
		const char* arg_str = argv[i];
		
		arg_str_len = strlen(arg_str);
		if (*arg_str == '-' && arg_str_len > 1)
		{
			switch(arg_str[1])
			{
				/* basename argument */
				case 'b':
				{
					if (arg_str[2] == 0)
					{
						/* case: "-b name" where idx[0] = "-b" and idx[1] = "name" */
						if (i + 1 < argc)
							basename = argv[i += 1];
						else
							fputs("-b ignored\n", stderr);
					}
					else
						/* case: -bname */
						basename = arg_str+2;
					
					break;
				}
				/* detect argument */
				case 'd':
				{
					test_mode = 1;
					break;
				}
				/* encrypt argument */
				case 'e':
				{
					encrypt_mode = 1;
					break;
				}
				/* help argument */
				case 'h':
				case '?':
				{
					show_usage(argv[0]);
					return 0;
				}
				/* Set custom key tables */
				case 'k':
				{
					const char *ktblname = NULL;
					
					if (arg_str[2] == 0)
					{
						if (i + 1 < argc)
							ktblname = argv[i += 1];
						else
							fputs("-k ignored\n", stderr);
					}
					else
						ktblname = arg_str+2;

					if(ktblname)
					{
						/* Key tables file should be in little endian */
						unsigned char buf[256];
						FILE *kf = fopen(ktblname, "rb");

						if(kf && fread(buf, 4, 64, kf) == 64)
						{
							size_t i = 0;
							unsigned char *x = buf;
							
							for(; i < 64; i++, x += 4)
								custom_ktbl[i] =
									x[0] |
									(x[1] << 8) |
									(x[2] << 16) |
									(x[3] << 24);

							custom_ktbl[64] = 1;
						}
						else
							perror(ktblname);

						if(kf) fclose(kf);
					}
					
					break;
				}
				/* show license argument */
				case 'l':
				{
					/* Most strings need to be separated to prevent '509' string length limit */
					puts("Copyright (c) 2044 Dark Energy Processor Corporation\n");
					puts("Permission is hereby granted, free of charge, to any person obtaining a\n"
						 "copy of this software and associated documentation files (the \"Software\"),\n"
						 "to deal in the Software without restriction, including without limitation\n"
						 "the rights to use, copy, modify, merge, publish, distribute, sublicense,\n"
						 "and/or sell copies of the Software, and to permit persons to whom the\n"
						 "Software is furnished to do so, subject to the following conditions:\n");
					puts("The above copyright notice and this permission notice shall be included in\n"
						 "all copies or substantial portions of the Software.\n");
					puts("THE SOFTWARE IS PROVIDED \"AS IS\", WITHOUT WARRANTY OF ANY KIND, EXPRESS\n"
						 "OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,\n"
						 "FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE\n"
						 "AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER\n"
						 "LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING\n"
						 "FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER\n"
						 "DEALINGS IN THE SOFTWARE.\n");
					puts("The following software is used in this program: md5\nThe license of the program are below\n");
					puts("md5.h -- Header file for implementation of MD5\n"
						 "RSA Data Security, Inc. MD5 Message Digest Algorithm\n"
						 "Created: 2/17/90 RLR\n"
						 "Revised: 12/27/90 SRD,AJ,BSK,JT Reference C version\n"
						 "Revised (for MD5): RLR 4/27/91\n"
						 "* G modified to have y&~z instead of y&z\n"
						 "* FF, GG, HH modified to add in last register done\n"
						 "* Access pattern: round 2 works mod 5, round 3 works mod 3\n"
						 "* distinct additive constant for each step\n"
						 "* round 4 added, working mod 7\n");
					puts("md5.c is modified a bit so that it does compile under C89. "
						 "To see what are the changes, compare it with original md5.c\n\n"
						 "Copyright (C) 1990, RSA Data Security, Inc. All rights reserved.\n\n"
						 "License to copy and use this software is granted provided that "
						 "it is identified as the \"RSA Data Security, Inc. MD5 Message "
						 "Digest Algorithm\" in all material mentioning or referencing this "
						 "software or this function.\n");
					puts("License is also granted to make and use derivative works "
						 "provided that such works are identified as \"derived from the RSA "
						 "Data Security, Inc. MD5 Message Digest Algorithm\" in all "
						 "material mentioning or referencing the derived work.\n\n"
						 "RSA Data Security, Inc. makes no representations concerning "
						 "either the merchantability of this software or the suitability "
						 "of this software for any particular purpose. It is provided \"as "
						 "is\" without express or implied warranty of any kind.\n");
					puts("These notices must be retained in any copies of any part of this "
						 "documentation and/or software.\n");
					return 0;
				}
				/* Set key prefix */
				case 'p':
				{
					if (arg_str[2] == 0)
					{
						if (i + 1 < argc)
							default_prefix = argv[i += 1];
						else
							fputs("-p ignored\n", stderr);
					}
					else
						default_prefix = arg_str+2;
					
					break;
				}
				/* Set name sum */
				case 's':
				{
					const char *sum_name = NULL;
					unsigned short namesum_temp;

					if (arg_str[2] == 0)
					{
						if (i + 1 < argc)
							sum_name = argv[i += 1];
						else
							fputs("-s ignored\n", stderr);
					}
					else
						sum_name = arg_str+2;

					if(sscanf(sum_name, "%hu", &namesum_temp) == 1)
						def_name_sum = namesum_temp;
					else
						fputs("-s ignored\n", stderr);
					
					break;
				}
				case 'V':
				case 'v':
				{
					printf("HonokaMiku in ANSI C with libhonoka %s (%d)\n"
						 "Copyright (c) 2044 Dark Energy Processor Corporation\nLicensed under terms of MIT license.\n",
						 honokamiku_version_string(), (int)(honokamiku_version()));
					return 0;
				}
				default:
				{
					if (!map_letter_to_gamefile(arg_str + 1, &expected_id, &expected_mode))
						fprintf(stderr, "%s ignored\n", arg_str);

					if(expected_id == honokamiku_gamefile_unknown)
						is_custom = 1;
					
					break;
				}
			}
		}
		else
			if (input_arg == 0)
				input_arg = i;
			else if (output_arg == 0)
				output_arg = i;
			else
				fprintf(stderr, "\"%s\" ignored\n", arg_str);
	}
	
	/* Set filename pointer */
	if (input_arg > 0)
		file_input = argv[input_arg];
	else
		file_input = argv[-input_arg]+2;
	
	if (output_arg == 0)
		/* If we did not see output filename, overwrite file later */
		file_output = file_input;
	else if (output_arg > 0)
		file_output = argv[output_arg];
	else
		file_output = argv[-output_arg]+2;

	is_stdin = memcmp(file_input, "-", 2) == 0;
	
	/* Check if we're under encrypt mode */
	if (encrypt_mode == 1 && expected_id == honokamiku_gamefile_unknown && !is_custom)
	{
		/* -e requires -w, -j, -t, -k, or -c switch */
		fprintf(stderr, "-e requires -w, -j, -t, -x, or -c switch\n");
		return (-1);
	}

	/* Reading from stdin requires basename flag */
	if (is_stdin && basename == NULL)
	{
		/* Reading from stdin requires -b switch */
		fprintf(stderr, "Reading from stdin requires -b switch\n");
		return (-1);
	}

	/* Custom game file requires key tables, prefix, and sum name set */
	if (is_custom &&
		(custom_ktbl[64] == 0 || !default_prefix)
	)
	{
		fprintf(stderr, "Custom game file requires -k and -p switch\n");
		return (-1);
	}
	else if (!is_custom)
	{
		custom_ktbl[64] = 0;
		def_name_sum = (-1);
		default_prefix = NULL;
	}

	if (basename == NULL) basename = file_input;
	if (custom_ktbl[64]) select_ktbl = custom_ktbl;
	
	/* Ok open file */
	file = is_stdin ? stdin : fopen(file_input, "rb");
	if (file == NULL)
	{
		perror(file_input);
		return (-1);
	}

	/* Load input file */
	if (encrypt_mode)
	{
		if(honokamiku_encrypt_init(
			dctx,
			expected_mode,
			expected_id,
			default_prefix,
			select_ktbl,
			def_name_sum,
			basename,
			file_header,
			16) != HONOKAMIKU_ERR_OK
		)
		{
			/* Failed to initialize encrypter */
			fprintf(stderr, "%s: Encrypter initialization failed\n", file_input);
			return (-1);
		}
	}
	else
	{
		/* Read 4 bytes at first */
		if(fread(file_header, 1, 4, file) != 4)
		{
			/* Too small */
			fprintf(stderr, "%s: File is too small\n", file_input);
			return (-1);
		}

		if (expected_id != honokamiku_gamefile_unknown || is_custom)
		{
			if(honokamiku_decrypt_init(dctx, expected_mode, expected_id, default_prefix, basename, file_header) != HONOKAMIKU_ERR_OK)
			{
				fprintf(test_mode ? stdout : stderr, "%s: Cannot decrypt with specificed gamefile!\n", file_input);
				return test_mode ? 0 : (-1);
			}
		}
		else
		{
			expected_id = honokamiku_decrypt_init_auto(dctx, basename, file_header);

			if (expected_id == honokamiku_gamefile_unknown)
			{
				fprintf(test_mode ? stdout : stderr, "%s: Unknown gamefile!\n", file_input);
				return test_mode ? 0 : (-1);
			}
		}

		if (honokamiku_decrypt_is_final_init(dctx))
		{
			/* Read 12 bytes */
			if(fread(file_header, 1, 12, file) != 12)
			{
				/* Too small again */
				fprintf(stderr, "%s: File is too small\n", file_input);
				return (-1);
			}

			if(honokamiku_decrypt_final_init(dctx, expected_id, select_ktbl, def_name_sum, file_input, file_header) != HONOKAMIKU_ERR_OK)
			{
				/* Unknown */
				fprintf(stderr, "%s: Unknown V3+ decryption method\n", file_input);
				return (-1);
			}
		}

		if (test_mode)
		{
			printf("%s: %s gamefile version %d!\n", file_input, gamefile_to_string(expected_id), dctx->dm);
			return 0;
		}

		fprintf(stderr, "%s: %s gamefile version %d!\n", file_input, gamefile_to_string(expected_id), dctx->dm);
	}

	/* Allocate file contents */
	if((file_buffer = malloc(file_contents_size)) == NULL)
	{
		fprintf(stderr, "%s: Not enough memory\n", file_input);
		return (-1);
	}

	/* Decrypt/encrypt routines */
	{
		size_t v1c = 0;
		size_t read_bytes;
		unsigned char *byte_buffer;

		byte_buffer = malloc(BUFFER_SIZE);

		if(byte_buffer == NULL)
		{
			/* Not enough memory */
			fprintf(stderr, "%s: Not enough memory\n", file_input);
			return (-1);
		}

		if (dctx->dm == 1 && !encrypt_mode)
		{
			v1c = 4;
			memcpy(byte_buffer, file_header, 4);
		}

		while((read_bytes = fread(byte_buffer + v1c, 1, BUFFER_SIZE - v1c, file) + v1c))
		{
			size_t free_size;
			v1c = 0;

			for(free_size = file_contents_size - file_contents_length; read_bytes > free_size; )
			{
				if(read_bytes > free_size)
				{
					char *temp = realloc(file_buffer, file_contents_size *= 2);

					if(temp == NULL)
					{
						free(file_buffer);
						fprintf(stderr, "%s: Not enough memory\n", file_input);
						return (-1);
					}

					file_buffer = temp;
				}
				free_size = file_contents_size - file_contents_length;
			}

			honokamiku_decrypt_block(dctx, byte_buffer, read_bytes);
			memcpy(file_buffer + file_contents_length, byte_buffer, read_bytes);
			file_contents_length += read_bytes;
		}

		free(byte_buffer);
	}

	fclose(file);

	/* Start open output */
	file = memcmp(file_output, "-", 2) == 0 ? stdout : fopen(file_output, "wb");
	if(file == NULL)
	{
		perror(file_output);
		return (-1);
	}

	/* Write the header first on encrypting */
	if(encrypt_mode)
	{
		header_size = honokamiku_header_size(dctx->dm);

		if(header_size > 0 && fwrite(file_header, 1, header_size, file) != header_size)
		{
			perror(file_output);
			return (-1);
		}
	}
	
	/* Write data, close, and free memory*/
	if(fwrite(file_buffer, 1, file_contents_length, file) != file_contents_length)
	{
		perror(file_output);
		return (-1);
	}
	
	free(file_buffer);
	if (file != stdout) fclose(file);
	
	return 0;
}
