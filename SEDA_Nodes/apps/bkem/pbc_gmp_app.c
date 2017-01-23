
#define MINI_GMP 1
#define PBC_SCHEME 1

#if PBC_SCHEME
#include "pbc_gmp_app.h"

void setup_global_system(bkem_global_params_t *gps, const char *pstr, int N) {
    // init global parameters
    bkem_global_params_t params;
    params = malloc(sizeof(struct bkem_global_params_s));
#if MEASURE_TIME
	clock_init();
#endif
    // Compute A, B system params
//    params->B = (int) sqrt(N);
    params->B = (int) (N);	
	
    params->A = (N + params->B - 1) / params->B;

    params->N = params->A * params->B;

    // Init pairing
  pairing_init_set_str(params->pairing, pstr);

    *gps = params;
}

void free_global_params(bkem_global_params_t gbs) {
    if (!gbs)
        return;

    pairing_clear(gbs->pairing);
    free(gbs);
}

void free_pubkey(pubkey_t pk, bkem_global_params_t gbs) {
    if (!pk)
        return;

    element_clear(pk->g);

    int i;
    for (i = 0; i < 2 * gbs->B; ++i) {
        element_clear(pk->g_i[i]);
    }

    for (i = 0; i < gbs->A; ++i) {
        element_clear(pk->v_i[i]);
    }
}

void free_bkem_system(bkem_system_t sys, bkem_global_params_t gbs) {
    if (!sys)
        return;

    free_pubkey(sys->PK, gbs);

    int i;
    for (i = 0; i < gbs->N; ++i) {
        element_clear(sys->d_i[i]);
    }
}

//#define BLACK   "\033[0;30;49m"
#define RED     "\x1b[0;31;49m"
//#define GREEN   "\x1b[0;32;49m"
//#define YELLOW  "\x1b[0;33;49m"
//#define BLUE    "\x1b[0;34;49m"
//#define MAGENTA "\x1b[0;35;49m"
//#define CYAN    "\x1b[0;36;49m"
//#define WHITE   "\x1b[0;37;49m"
#define DEFAULT "\x1b[0m"

#ifndef NDEBUG

#define MEASURE_TIME 1 //for time measurement

#if MEASURE_TIME
#include <sys/time.h>
/**
 * @defgroup clock Clock Handling
 * Default implementation of internal clock. You should redefine this if
 * you do not have time() and gettimeofday().
 * @{
 */
#include "clock.h"
#ifndef CLOCK_SECOND
# define CLOCK_SECOND 1000
#endif
typedef uint32_t clock_time_t;

static inline void
print_timestamp() {
	static char timebuf[32];
	snprintf(timebuf, 32, "%u.%03u", 
		  clock_time() / CLOCK_SECOND, 
		  clock_time() % CLOCK_SECOND);
	printf("(%s)",timebuf);
}
#else
#endif
#endif
#define DUMP_MODE 0 // DUMP pre calculate keys
#define USE_COMPRESS 1 //use elliptic curve point compression to lesson the size of data

void dump_element(char* name, element_ptr e)
{
	char *buf = pbc_malloc(e->field->fixed_length_in_bytes +1);

//	element_printf("element= [%B]\n",e);
//	printf("[%s size=%d] \n",name,e->field->fixed_length_in_bytes);
	e->field->snprint(buf, e->field->fixed_length_in_bytes,e);
	printf("char %s[%d] = \"%s\";\n",name,e->field->fixed_length_in_bytes,buf);
	pbc_free(buf);
}


void dump_element_binary_compressed(char*name,element_ptr e)
{
	int size= element_length_in_bytes_compressed(e),i;
	if( size > 200 ) {
		printf("[%s] size = %d \n",name,size);
		return;
	}
	
	unsigned char *buf2= pbc_malloc(element_length_in_bytes_compressed(e));
	element_to_bytes_compressed(buf2, e);
	printf("\nunsigned char %s[%d] = {",name,size);
	for(i=0;i<size;i++)
	{
		printf("0x%02x",buf2[i]);
		if(i<size-1)
			printf(",");
	}	
	printf("};\n");
	pbc_free(buf2);
}


void dump_element_binary2(char*name,element_ptr e)
{
	unsigned char *buf2= pbc_malloc(e->field->fixed_length_in_bytes +1);
	int size= e->field->to_bytes(buf2, e);
	int i;
	printf("\nunsigned char %s[%d] = {",name,e->field->fixed_length_in_bytes);
	for(i=0;i<e->field->fixed_length_in_bytes;i++)
	{
		printf("0x%02x",buf2[i]);
		if(i<e->field->fixed_length_in_bytes-1)
			printf(",");
	}	
	printf("};\n");
	pbc_free(buf2);
}

void dump_element_binary(char*name,element_ptr e)
{
	dump_element_binary_compressed(name,e);
}

#if 1 //for decryption test

//
/*
//32
unsigned char pk_g[10] = {0x30,0xd3,0x5a,0x34,0x04,0x16,0x06,0xd3,0x75,0x1a};

unsigned char pk_g_0[10] = {0x13,0xff,0xd4,0xf1,0x14,0x32,0xc8,0x33,0x86,0xc0};

unsigned char pk_g_1[10] = {0x1d,0x9b,0xd4,0x72,0x6f,0x1c,0x8f,0x28,0xe5,0xf9};

unsigned char pk_g_2[10] = {0x0e,0x3d,0xf1,0xd4,0x5a,0x2c,0x31,0x7d,0xf0,0xee};

unsigned char pk_g_3[10] = {0x20,0xb1,0xc0,0x28,0xc5,0x2f,0xb9,0xd3,0x7f,0x96};

unsigned char pk_g_4[10] = {0x01,0xe0,0x3d,0xdd,0x30,0x30,0x97,0x70,0x39,0x63};

unsigned char pk_g_5[10] = {0x39,0xdc,0xf4,0x9d,0x9b,0x33,0x09,0xcf,0xd0,0x98};

unsigned char pk_v_0[10] = {0x2d,0x22,0x67,0x25,0x1c,0x06,0x2c,0xde,0xbd,0x7d};

unsigned char pr_0[10] = {0x23,0xb6,0xd1,0x00,0xbf,0x33,0xe7,0xdd,0xd6,0x86};

unsigned char pr_1[10] = {0x01,0x2f,0xc8,0x8d,0x9c,0x24,0x44,0xcb,0xa4,0xd9};

unsigned char pr_2[10] = {0x1d,0xf7,0x08,0x17,0x27,0x1f,0x1e,0x61,0xd9,0x41};

unsigned char enc[10] = {0x1d,0xb5,0x96,0x5e,0x08,0x39,0x19,0xd4,0xf8,0x0e};

unsigned char hdr_0[10] = {0x04,0xd0,0x43,0x80,0x41,0x1e,0xcb,0x2c,0xf1,0xd8};

unsigned char hdr_1[10] = {0x34,0x24,0xcf,0x4b,0x4b,0x10,0xa8,0xa0,0x0f,0x23};
//*/

//
/*
unsigned char pk_g[42] = {0x09,0x93,0x8c,0xa7,0xe5,0xa6,0xca,0x8f,0x4d,0xee,0x32,0xa6,0xd9,0xeb,0x62,0xed,0xe1,0xc6,0xb8,0x00,0xae,0x11,0x3d,0xbe,0x56,0x19,0xc0,0x1e,0x13,0x31,0xd4,0x70,0xa1,0x1b,0x18,0xc3,0x7a,0x58,0xcf,0x4b,0x4b,0x52};

unsigned char pk_g_0[42] = {0x1d,0xb7,0xb9,0xea,0x1e,0xda,0x77,0x69,0xf4,0x90,0x3e,0x87,0x2e,0xbb,0xbb,0x7f,0xe4,0x79,0x9b,0x5a,0x62,0x0b,0xa0,0xa0,0x3d,0x30,0x3a,0xd9,0xd4,0xde,0x13,0x2a,0x8a,0x6a,0xd3,0x03,0x7f,0x21,0x08,0x0e,0x56,0x89};

unsigned char pk_g_1[42] = {0x11,0x6f,0x7e,0x30,0xfa,0x04,0xbc,0xda,0xaa,0xf7,0xa3,0x5d,0x99,0x92,0x9e,0xc4,0x4e,0x2e,0x2e,0x84,0x9b,0x14,0x9a,0x3c,0x57,0xc0,0x06,0xea,0x42,0xdc,0x36,0x69,0xe2,0xd4,0x89,0x2f,0xa7,0x38,0x7e,0x56,0x06,0x76};

unsigned char pk_g_2[42] = {0x1f,0xc0,0xac,0x88,0x11,0x94,0x81,0xa0,0x0b,0x54,0xd3,0x58,0xe3,0xe3,0xbb,0xe5,0xcb,0xb2,0x9b,0x17,0x78,0x0b,0x2d,0x53,0x10,0x98,0x43,0xe7,0x1d,0xe1,0xd5,0x86,0x82,0xa8,0x49,0x77,0x60,0x4e,0xfd,0x80,0xcb,0x2a};

unsigned char pk_g_3[42] = {0x1e,0x1c,0xd0,0xb8,0x9a,0x56,0x5b,0x48,0x5c,0xfa,0xac,0xaf,0xa5,0x75,0x3c,0x29,0x03,0xed,0xc1,0xa8,0xf8,0x1e,0xa4,0xf3,0xf1,0x46,0xf8,0x2d,0xc0,0x25,0x44,0x1f,0xe6,0x19,0xbc,0xa5,0x2f,0xbb,0x06,0x6f,0x38,0x10};

unsigned char pk_g_4[42] = {0x1a,0x0e,0x04,0xf2,0x54,0x7e,0xb5,0xa8,0xdf,0x02,0xd1,0xc0,0x13,0xd4,0x81,0xc1,0x66,0xe1,0xdd,0x09,0xc1,0x0e,0x6d,0x40,0xbb,0xbf,0xad,0xcd,0xb9,0x34,0x3e,0x80,0x72,0xa0,0xe6,0x85,0x3d,0x44,0xf3,0xae,0x27,0x3d};

unsigned char pk_g_5[42] = {0x10,0xe0,0x72,0x71,0x34,0x62,0xbc,0x87,0x55,0x42,0xa5,0x2c,0x6d,0x1f,0x81,0xd3,0x3a,0x08,0x76,0xec,0xf7,0x1b,0x3d,0x3d,0xbf,0xa9,0x5f,0xfe,0xc5,0x8a,0x56,0xee,0x2b,0x86,0x47,0x13,0x01,0xa2,0x9e,0xf3,0x23,0x10};

unsigned char pk_v_0[42] = {0x11,0xf8,0x70,0x61,0x23,0x40,0xa3,0xe5,0x07,0x1a,0x7b,0xa2,0x86,0x38,0x50,0xda,0xac,0x97,0x11,0x30,0x9c,0x0c,0xe0,0x8f,0xa1,0x1c,0x4b,0x2e,0xa4,0xbe,0xc9,0x73,0xe9,0x67,0x78,0x60,0xa0,0xc5,0x0e,0x2f,0x74,0x5b};

unsigned char pr_0[42] = {0x09,0x70,0xaf,0x29,0x5d,0xd9,0x6f,0x0d,0xd7,0xef,0x28,0x25,0xe1,0xe3,0x8b,0xf1,0x20,0x8b,0xfe,0x7e,0xf4,0x12,0x41,0xdc,0xc0,0x49,0x29,0x49,0x6c,0xf7,0x84,0x07,0x29,0x65,0x45,0x48,0x7e,0xb1,0x8c,0xd0,0xb9,0xa1};

unsigned char pr_1[42] = {0x0d,0x14,0x35,0x66,0x8b,0x29,0xc5,0x47,0xc6,0x49,0x96,0xdd,0xb5,0x9d,0xbb,0x96,0x8c,0x38,0x31,0x1f,0x1f,0x1f,0xb5,0xc9,0x64,0x7d,0x93,0x23,0x33,0x3b,0x5b,0x34,0x7d,0x06,0xd5,0xf1,0xb9,0x37,0x2c,0x6b,0x79,0x03};

unsigned char pr_2[42] = {0x21,0x74,0x68,0x83,0xaf,0x58,0xcf,0xf0,0xad,0xd7,0xd0,0x3f,0x42,0xce,0x19,0xaf,0x6e,0x2b,0xc2,0x7b,0xd2,0x0b,0x08,0xae,0xd4,0x6d,0xba,0x72,0xb8,0x88,0x2d,0x06,0x2e,0xd1,0xcc,0x98,0x17,0x32,0x4b,0x90,0x34,0x2e};
unsigned char enc[42] = {0x04,0x13,0x74,0x71,0xdf,0x2a,0xcd,0x50,0x53,0xae,0x39,0xdd,0x26,0x96,0x1b,0x73,0x18,0x0a,0x51,0xac,0x39,0x0a,0xc5,0xe8,0xc6,0xb9,0x8b,0x36,0xd3,0x8e,0x92,0x43,0xa0,0x47,0xbd,0x0a,0xbe,0x54,0x33,0x68,0xa7,0xec};

unsigned char hdr_0[42] = {0x08,0x9d,0x92,0x90,0x05,0xc2,0x0b,0x85,0xd0,0xf5,0x0d,0xb2,0x84,0xba,0x6f,0xe4,0xa8,0xfd,0x15,0x23,0x1e,0x09,0x56,0x44,0x24,0x61,0xb8,0x7d,0x95,0xa9,0x9f,0x1c,0x48,0x39,0xb1,0x3b,0x4e,0x42,0xa5,0x18,0x68,0xe3};

unsigned char hdr_1[42] = {0x19,0xa8,0xdb,0x6f,0x49,0x41,0x1e,0x3e,0x61,0x48,0xc5,0x07,0x98,0xec,0x9c,0x0c,0x81,0x88,0x5a,0x4f,0xe3,0x06,0x79,0x5e,0x33,0xc6,0xcb,0x05,0xab,0xa1,0x5e,0x9d,0x0d,0xf1,0xa9,0x1b,0x00,0xcb,0x74,0x04,0xcd,0xbd};
//*/
#endif
//
/* comression r=32
unsigned char pk_g[6] = {0x07,0xf0,0xe0,0xaa,0xa2,0x01};

unsigned char pk_g_0[6] = {0x11,0xd0,0x07,0xa1,0x22,0x00};

unsigned char pk_g_1[6] = {0x22,0x9a,0x39,0x9c,0xb0,0x00};

unsigned char pk_g_2[6] = {0x26,0x1f,0x44,0xe9,0x99,0x00};

unsigned char pk_g_3[6] = {0x12,0x40,0x0c,0xbe,0x28,0x01};

unsigned char pk_g_4[6] = {0x0c,0x65,0xeb,0x83,0x61,0x01};

unsigned char pk_g_5[6] = {0x35,0xd6,0xc9,0x11,0xaa,0x00};

unsigned char pk_v_0[6] = {0x11,0xbe,0x5a,0x96,0x0e,0x00};

unsigned char pr_0[6] = {0x18,0x24,0x48,0x8a,0x8a,0x00};

unsigned char pr_1[6] = {0x31,0xad,0x50,0xda,0x41,0x00};

unsigned char pr_2[6] = {0x1b,0x87,0x81,0x46,0xba,0x01};

unsigned char t[4] = {0xd4,0x4e,0xfa,0xab};

unsigned char K[10] = {0x32,0xce,0xc7,0x9d,0x88,0x2e,0x81,0xdc,0xb5,0x5e};

unsigned char hdr_0[6] = {0x31,0xa1,0x3b,0xd1,0x79,0x01};

unsigned char hdr_1[6] = {0x20,0xf4,0xea,0x7d,0xef,0x00};
unsigned char *param = "type a\nq 255684771779\nh 60\nr 4261412863\nexp2 32\nexp1 25\nsign1 -1\nsign0 -1\n";
//
/*
///* compressed r=64
unsigned char pk_g[10] = {0x09,0x2d,0x92,0x72,0x63,0x99,0x3e,0x06,0xeb,0x01};

unsigned char pk_g_0[10] = {0x44,0x58,0xc0,0x99,0xbb,0xb5,0x0e,0x71,0x37,0x00};

unsigned char pk_g_1[10] = {0x31,0xc5,0x2b,0x21,0x50,0x72,0xfc,0x04,0xd1,0x01};

unsigned char pk_g_2[10] = {0x20,0x5f,0x04,0x0b,0x24,0x82,0x06,0xc6,0xe8,0x01};

unsigned char pk_g_3[10] = {0x30,0x1b,0xd1,0x94,0xf3,0x83,0xba,0x32,0x38,0x00};

unsigned char pk_g_4[10] = {0x4f,0xc0,0xc9,0x6e,0xc6,0x29,0x4b,0x1e,0x02,0x00};

unsigned char pk_g_5[10] = {0x29,0x9f,0xcf,0x51,0x6c,0xba,0xc1,0x50,0x42,0x00};

unsigned char pk_v_0[10] = {0x0e,0x52,0x60,0x52,0xa1,0x7f,0xff,0xbc,0x0a,0x00};

unsigned char pr_0[10] = {0x37,0x98,0xcb,0xce,0xf1,0x56,0x62,0xc2,0x04,0x01};

unsigned char pr_1[10] = {0x4d,0x9d,0x26,0xe5,0x88,0xc3,0xe9,0x2d,0x10,0x00};

unsigned char pr_2[10] = {0x09,0x50,0x43,0x80,0x6f,0x43,0x40,0x71,0xf6,0x01};

unsigned char t[8] = {0x83,0xaa,0x1b,0x1e,0xc3,0x91,0x81,0x5f};

unsigned char K[18] = {0x4a,0x7a,0x33,0x9d,0x72,0x66,0x8c,0x26,0xc3,0x25,0x42,0x1a,0x5c,0x35,0x9d,0x9e,0x29,0x9e};

unsigned char hdr_0[10] = {0x16,0x54,0x72,0x8e,0x35,0x36,0x21,0x10,0x81,0x00};

unsigned char hdr_1[10] = {0x42,0x35,0x61,0x56,0xf3,0x48,0xdb,0x8e,0x78,0x01};
unsigned char *param ="type a\nq 1549526502191602249643\nh 84\nr 18446744073709550591\nexp2 64\nexp1 10\nsign1 -1\nsign0 -1\n";
//*/	
//
/* compressed r=128
unsigned char pk_g[18] = {0x00,0x09,0x07,0x5b,0xf0,0xea,0x82,0x1d,0xd2,0x77,0x18,0xd7,0x61,0xb1,0x05,0x5a,0x20,0x01};

unsigned char pk_g_0[18] = {0x04,0x44,0x22,0xcf,0x53,0x59,0x20,0x02,0x23,0xef,0x11,0xa1,0x9f,0xdd,0x13,0xed,0xc5,0x00};

unsigned char pk_g_1[18] = {0x06,0x82,0xf1,0x04,0x60,0xa6,0x3f,0x61,0xe2,0x8c,0xfb,0x02,0x5b,0x50,0xd4,0xff,0xf7,0x01};

unsigned char pk_g_2[18] = {0x02,0x5d,0x55,0x18,0xad,0x08,0xbe,0x12,0x13,0xd8,0xdd,0x95,0x8f,0x1b,0xab,0x7d,0xfc,0x00};

unsigned char pk_g_3[18] = {0x02,0xe0,0x72,0x74,0x80,0x26,0x48,0x2d,0xd8,0xea,0xa3,0xf2,0xfc,0xee,0xf3,0x19,0x66,0x01};

unsigned char pk_g_4[18] = {0x07,0x05,0xd7,0x29,0x41,0x25,0x77,0xb3,0x20,0xba,0x5e,0x1c,0x8f,0xa2,0x7d,0xd7,0x50,0x00};

unsigned char pk_g_5[18] = {0x05,0x9f,0xbc,0x9d,0x9d,0x7d,0xec,0x4e,0x63,0xed,0x96,0x5c,0xa6,0x8f,0x3a,0x47,0x88,0x00};

unsigned char pk_v_0[18] = {0x09,0x79,0xa9,0xcd,0x0f,0x2c,0xb6,0xce,0x47,0x41,0x01,0x75,0x5c,0x9b,0x1e,0x53,0xfc,0x01};

unsigned char pr_0[18] = {0x03,0xc3,0x01,0x8b,0x9e,0xf3,0x3c,0x1a,0x56,0xec,0x1e,0xe9,0xb8,0x17,0xe9,0x67,0x9d,0x01};

unsigned char pr_1[18] = {0x08,0xbf,0xa6,0x06,0x69,0x0b,0x58,0xe7,0xe5,0x7e,0xef,0x78,0xff,0x7b,0x4e,0xbb,0xdc,0x01};

unsigned char pr_2[18] = {0x05,0xf8,0x8b,0x5d,0xc0,0xa5,0x0c,0x0f,0x9a,0x83,0x8f,0x79,0x48,0x44,0x91,0x07,0x6e,0x00};

unsigned char t[16] = {0x4e,0xc2,0xc3,0xd6,0x8e,0x37,0xc8,0xcf,0x61,0x6b,0x81,0x95,0xeb,0x5f,0x47,0xc4};

unsigned char K[34] = {0x0a,0x31,0xa8,0x3e,0x7c,0xf3,0xa7,0x56,0x95,0x0e,0x4d,0xa4,0x86,0xd4,0xef,0x61,0xc5,0x06,0x79,0x7b,0xc7,0x74,0x21,0x65,0x1d,0xb6,0x33,0x60,0x8f,0x30,0x71,0x67,0xb4,0xed};

unsigned char hdr_0[18] = {0x06,0xe1,0x18,0x52,0x52,0xbe,0x2d,0x33,0x6e,0x7d,0x02,0x3d,0x4d,0xfc,0xe7,0xcb,0xb1,0x01};

unsigned char hdr_1[18] = {0x06,0x51,0x8f,0x2a,0xdb,0x8a,0x49,0x74,0x48,0xfb,0xba,0xa0,0xce,0x55,0x08,0x0a,0x79,0x00};
unsigned char *param ="type a\nq 4083388403051261561560495289181215391731\nh 12\nr 340282366920938463463374607431767949311\nexp2 128\nexp1 18\nsign1 -1\nsign0 -1\n";
//*/	
///* compression r =160
unsigned char pk_g[22] = {0x15,0xd9,0x81,0x46,0x2c,0x1b,0x49,0x64,0x9c,0x8b,0x3d,0x24,0x01,0x10,0x96,0x42,0xc1,0x82,0x74,0x83,0x65,0x01};
unsigned char pk_g_0[22] = {0x10,0x4d,0x22,0x3d,0x32,0x4a,0xb7,0x87,0x70,0x8b,0xae,0x3c,0x4d,0x41,0x90,0x46,0x5a,0x26,0x56,0xd9,0x03,0x01};
unsigned char pk_g_1[22] = {0x4c,0xb3,0x74,0x7d,0x03,0x93,0x95,0x4e,0x92,0x9b,0xed,0xff,0x8d,0x6a,0x8b,0xd6,0xdb,0x4b,0x11,0xf6,0x19,0x00};
unsigned char pk_g_2[22] = {0x0c,0x0c,0x17,0xd4,0xe0,0x45,0x08,0x7f,0x8e,0xbd,0x2b,0x37,0x6b,0x23,0x9f,0x33,0xb6,0x2b,0x92,0x1e,0x72,0x01};
unsigned char pk_g_3[22] = {0x06,0x4a,0x44,0x12,0x92,0xec,0xb5,0x9f,0x46,0x3e,0xcd,0x65,0xb8,0x2b,0xad,0x7c,0xe7,0x88,0x58,0xa0,0x8f,0x00};
unsigned char pk_g_4[22] = {0x51,0xe1,0x38,0xd2,0x69,0xd7,0x9f,0x8d,0xd5,0x70,0xf0,0x6a,0x49,0x8f,0xcb,0xb6,0x4e,0x51,0xbf,0x66,0xa4,0x01};
unsigned char pk_g_5[22] = {0x2b,0xf5,0x71,0xd9,0x66,0x38,0x05,0x74,0x45,0xbd,0x26,0x49,0xd5,0xc5,0xb5,0xa7,0x84,0x8e,0x53,0x1e,0x70,0x01};
unsigned char pk_v_0[22] = {0x2f,0x1e,0xb0,0xe0,0xe8,0x63,0x71,0xeb,0x80,0x6b,0xa5,0x9e,0x99,0x8d,0x16,0xe0,0x82,0xd7,0x4c,0x91,0xe7,0x00};
unsigned char pr_0[22] = {0x50,0x6e,0x68,0x73,0xc1,0x50,0x50,0x2a,0xed,0x1b,0xa5,0x0c,0x86,0xbd,0x6e,0xe4,0x0d,0x03,0x03,0xb5,0x26,0x00};
unsigned char pr_1[22] = {0x59,0xea,0xfa,0xbf,0xa7,0x2c,0x0b,0x30,0x3f,0xef,0x10,0xa2,0x4c,0x08,0x62,0x00,0x2c,0x17,0x7f,0x71,0xbe,0x01};
unsigned char pr_2[22] = {0x34,0x26,0xad,0x6b,0x81,0x2b,0x4a,0x69,0x15,0x4c,0xfd,0xd3,0xe8,0xef,0x2d,0x69,0xf7,0xd4,0x77,0x85,0x29,0x00};
unsigned char K[42] = {0x58,0x64,0x00,0xf3,0x54,0x07,0x96,0x46,0xb5,0xac,0x10,0x9c,0x2a,0x92,0x7f,0x50,0xcb,0xc7,0xe8,0xf5,0x8b,0x3b,0xe4,0xe7,0x38,0x0a,0x58,0xfe,0x41,0x3e,0x44,0xa5,0xfb,0x09,0xec,0x84,0x09,0xdf,0x32,0xe5,0x25,0x52};
unsigned char hdr_0[22] = {0x18,0x52,0x62,0x81,0x21,0xca,0x7f,0xed,0x31,0xa4,0xb2,0x1b,0xc6,0x76,0x7a,0x03,0xf1,0xe6,0x62,0x79,0x84,0x01};
unsigned char hdr_1[22] = {0x52,0xf0,0xba,0xba,0xd2,0xa4,0x02,0x41,0x36,0x4b,0x56,0xc9,0x7e,0xdb,0x89,0x63,0xbc,0x58,0xf0,0x41,0x53,0x00};
unsigned char *param ="type a\nq 140304157183766711301334895149728941069947499446463\nh 192\nr 730750818665451621361119245571504901405976559617\nexp2 159\nexp1 107\nsign1 1\nsign0 1";
//*/
//
/* compression r=224
unsigned char pk_g[30] = {0x04,0x7e,0x61,0x87,0x2d,0x5c,0x82,0x77,0xd1,0x8b,0x54,0xab,0x3a,0xa5,0x2e,0x20,0x16,0x52,0xd7,0x4a,0x07,0x24,0x68,0x8e,0x87,0x19,0xfc,0x5c,0xa9,0x01};

unsigned char pk_g_0[30] = {0x00,0x23,0x34,0xe7,0x0e,0xd7,0x78,0x4b,0x4c,0x33,0xb1,0xe6,0xf0,0xc0,0xe0,0xe3,0x87,0xaf,0x18,0x93,0x76,0xb1,0xf5,0x28,0x3f,0x58,0x3d,0x77,0x27,0x01};

unsigned char pk_g_1[30] = {0x03,0x24,0xfd,0xd0,0xae,0xc5,0xeb,0x7a,0xb1,0xbd,0xe6,0xc6,0x0e,0xa1,0xda,0x3c,0x19,0xd6,0xbf,0x98,0xa7,0xa9,0x88,0xb8,0x5a,0x74,0x23,0x99,0xcf,0x00};

unsigned char pk_g_2[30] = {0x08,0x56,0x1f,0x9c,0x8b,0x19,0xdf,0xee,0x8e,0x6e,0x88,0x8b,0xe7,0x1a,0xe9,0xa7,0xd8,0xdc,0xae,0x4c,0xce,0x5e,0x75,0xc4,0x14,0x15,0x8c,0x71,0x9a,0x00};

unsigned char pk_g_3[30] = {0x0c,0x8f,0x50,0x27,0x96,0x23,0xf3,0x16,0xc3,0x3d,0x9a,0xad,0x7d,0x85,0x5c,0x47,0x76,0x3e,0x82,0xbd,0xb4,0x32,0x8d,0x03,0x7d,0x06,0xad,0x88,0x25,0x01};

unsigned char pk_g_4[30] = {0x0b,0x78,0xab,0x65,0x8e,0x1f,0x4f,0xa2,0xa9,0x79,0x12,0xca,0xa9,0x05,0xe9,0xa0,0x73,0xfe,0xa0,0xae,0xad,0x58,0x78,0x4e,0x16,0x69,0x04,0x6a,0xe0,0x01};

unsigned char pk_g_5[30] = {0x01,0x26,0x82,0xad,0x8e,0x4b,0x73,0x76,0x4b,0x68,0x83,0xec,0x1a,0x8e,0x8f,0xc0,0x56,0xe8,0xd6,0x09,0xec,0xce,0x2d,0xac,0x86,0x1e,0xc3,0x00,0x1f,0x00};

unsigned char pk_v_0[30] = {0x0d,0x26,0xe0,0x0b,0xd9,0x0b,0xbd,0x3c,0xc0,0x11,0x60,0x9e,0xf7,0x35,0x8f,0x99,0xb6,0x1b,0x13,0xf2,0xbb,0x27,0xc9,0x48,0x5c,0x37,0xbc,0x3e,0x8f,0x01};

unsigned char pr_0[30] = {0x0f,0x96,0xf4,0xbb,0x55,0x43,0x17,0x2e,0x41,0x1e,0xca,0xd7,0x6e,0x68,0x8e,0x0c,0xa9,0xab,0xbb,0x6e,0xc1,0xda,0x4d,0x81,0x81,0xa4,0xae,0x5a,0x10,0x00};

unsigned char pr_1[30] = {0x02,0xa7,0xe0,0x57,0xe3,0x02,0x62,0x96,0x93,0x99,0x91,0x9f,0x0a,0x86,0x97,0x4b,0x87,0x68,0xd3,0x9f,0x19,0xd8,0x53,0xb3,0x00,0x6b,0xd0,0x10,0x29,0x01};

unsigned char pr_2[30] = {0x17,0xc7,0x40,0x7d,0xbf,0x25,0x92,0xca,0xa2,0xb6,0xab,0x9f,0x3a,0x74,0xc6,0xf3,0xba,0xe5,0xfe,0x77,0x1d,0xd8,0x97,0xac,0xe5,0x76,0xf7,0x05,0x6e,0x00};

unsigned char t[28] = {0xe3,0xb0,0x45,0x00,0xf6,0x83,0x57,0x00,0xe1,0x00,0x56,0x5d,0xd7,0xcf,0xb9,0x9d,0x89,0xc8,0xac,0x04,0x4c,0xc9,0xdb,0x85,0x37,0xd4,0x7e,0xa4};

unsigned char K[58] = {0x01,0x2f,0x30,0x97,0xfb,0x2b,0x15,0x6e,0x21,0x58,0xe3,0x93,0x1d,0x6a,0xa2,0xbd,0x0c,0x53,0x25,0x65,0x17,0x5a,0x9d,0x59,0x1a,0xe1,0xd7,0x32,0x39,0x05,0x45,0x12,0x32,0x7e,0xb7,0x8b,0x42,0x9b,0x90,0x36,0x42,0xb8,0xd8,0xde,0x88,0x1a,0xbf,0x65,0xe9,0x2e,0x52,0xb0,0xd7,0x73,0xeb,0x81,0xc7,0xb9};

unsigned char hdr_0[30] = {0x0d,0x89,0x52,0xff,0x66,0xff,0x8b,0xad,0xd1,0xcc,0x30,0x82,0x0e,0x1c,0x82,0x75,0x22,0xff,0x45,0x8f,0x34,0xd7,0x95,0x87,0x8a,0xec,0x3f,0x45,0x29,0x01};

unsigned char hdr_1[30] = {0x0e,0x9a,0x51,0x1d,0xa3,0x43,0xc3,0x0b,0xf3,0x2a,0x23,0x17,0x80,0x36,0x39,0xd0,0x7f,0x3e,0x7b,0x78,0x4f,0x55,0xdd,0x8b,0x0d,0xf2,0x77,0xdf,0x2b,0x00};
unsigned char *param ="type a\nq 647038720011615355071991235116158664648718766709340345604850053021671\nh 24\nr 26959946667150639794666301463173277693696615279555847733535418875903\nexp2 224\nexp1 149\nsign1 -1\nsign0 -1";
//*/
//
/* compression r=256
unsigned char pk_g[34] = {0x0a,0xd8,0x1b,0x47,0x95,0xd7,0x8a,0xb5,0x56,0x4e,0x2f,0x18,0x2c,0x77,0x67,0x21,0xc1,0x8f,0xc5,0x62,0xfd,0x41,0xcf,0x93,0x08,0xb6,0x8d,0x70,0xce,0x48,0x9b,0x22,0x8b,0x00};

unsigned char pk_g_0[34] = {0x03,0x48,0x63,0x84,0x0d,0xd4,0xe6,0x87,0x8f,0x81,0x72,0xc2,0x8b,0x19,0xb7,0x08,0xf6,0x2a,0x0b,0x9b,0xd1,0xe1,0x85,0x87,0xa0,0xa8,0x9f,0x16,0x98,0x85,0x2f,0x38,0x37,0x00};

unsigned char pk_g_1[34] = {0x19,0x33,0x92,0x95,0x93,0x49,0xe4,0xfc,0xe8,0xad,0x1f,0x46,0xdb,0x79,0xe2,0x53,0x66,0x32,0xbe,0x2a,0xe4,0x80,0xe0,0x63,0x8b,0x35,0xb0,0xce,0x73,0xd5,0x4f,0x29,0x05,0x01};

unsigned char pk_g_2[34] = {0x19,0xe2,0xb3,0xb2,0x40,0x5b,0x52,0x50,0xaa,0x97,0x51,0x97,0xbb,0xc5,0xaf,0xdf,0xa5,0x7e,0x04,0x27,0xca,0xa0,0x11,0x75,0x96,0xde,0x43,0x66,0x99,0xf2,0x23,0xb3,0xe8,0x00};

unsigned char pk_g_3[34] = {0x04,0xd3,0x3c,0x9a,0x2c,0x80,0x63,0x3d,0x4e,0xc1,0xf6,0xaa,0x2c,0xa1,0xa1,0x06,0xd1,0xd7,0x16,0xf0,0x06,0xb1,0x47,0x53,0xc6,0xb8,0x3a,0x50,0xb1,0xea,0x51,0x6b,0x37,0x01};

unsigned char pk_g_4[34] = {0x17,0xa2,0x47,0xc9,0x7e,0x51,0xfc,0xcf,0xc0,0xd4,0xc1,0x33,0xfc,0x62,0x67,0xe9,0xa7,0x6c,0x51,0xb6,0x95,0x89,0x0e,0x32,0x96,0x9a,0xa2,0xbf,0x41,0x4c,0x92,0xbe,0x08,0x00};

unsigned char pk_g_5[34] = {0x04,0xa7,0xae,0x55,0x4b,0xc9,0x23,0xa5,0x7a,0x85,0x8e,0x23,0x42,0xc4,0xa0,0xf5,0x01,0x3a,0x65,0x54,0xba,0xe5,0x6f,0xe5,0x39,0x17,0x68,0x22,0x4d,0x6e,0x36,0xe3,0x77,0x01};

unsigned char pk_v_0[34] = {0x1d,0x33,0xcf,0xa3,0x01,0xfc,0x14,0x3b,0xc8,0xd9,0xd1,0x49,0xa5,0xaa,0xdd,0xdf,0x19,0x55,0xc3,0xd8,0x1d,0xb6,0xf3,0x3a,0x5e,0x1f,0xfa,0xde,0x97,0x25,0x95,0x1b,0xf3,0x00};

unsigned char pr_0[34] = {0x1d,0xb4,0x61,0x48,0x17,0x1b,0x7a,0x0a,0x62,0x1b,0xef,0x8c,0xad,0x33,0xdf,0x0e,0xf0,0x90,0x71,0x28,0x49,0x9c,0x4e,0x8d,0x70,0xd8,0xaa,0x23,0x6e,0x69,0xa1,0xcb,0xae,0x00};

unsigned char pr_1[34] = {0x00,0x73,0xa6,0xb5,0x78,0x4b,0x1a,0xbf,0xe2,0xcb,0xda,0x77,0x72,0xb0,0xf3,0xc9,0x55,0xda,0xca,0xba,0xc0,0x76,0x60,0xb1,0xf2,0x17,0x70,0x19,0x4a,0xee,0x91,0x25,0x35,0x01};

unsigned char pr_2[34] = {0x18,0xda,0xc3,0x76,0x26,0x0f,0x5d,0xc9,0xb3,0xf9,0xd0,0x79,0x9b,0x53,0x91,0xb5,0x47,0x51,0x8e,0x7f,0x69,0x41,0xfb,0x45,0x40,0x5c,0x60,0x96,0x87,0x07,0x23,0x00,0x4f,0x00};

unsigned char t[32] = {0x55,0x90,0xda,0xf8,0x89,0xd0,0x38,0xe8,0x00,0xb5,0xa6,0x51,0x9c,0x6e,0x1f,0x6f,0xbd,0x3f,0x2c,0x59,0x48,0x44,0x0f,0x01,0xf4,0x49,0x3c,0x5e,0x8d,0x1e,0x93,0x4f};

unsigned char K[66] = {0x02,0xed,0x18,0x63,0x98,0x7e,0xf2,0x1f,0xd7,0x80,0xd7,0x19,0x56,0xd4,0xb8,0xde,0xe4,0x68,0xcf,0x23,0x88,0x2f,0x25,0x23,0x98,0xab,0x34,0xd7,0x86,0x34,0x1f,0xd8,0x71,0x02,0xa1,0x6f,0xe8,0x17,0xfa,0xdc,0x65,0x30,0xfb,0x70,0xa5,0xcb,0xa9,0xd4,0x9b,0x5e,0xd4,0x42,0x60,0xd2,0x46,0x5e,0x1d,0x3b,0x39,0x09,0x7d,0x81,0xd6,0x89,0xdb,0x41};

unsigned char hdr_0[34] = {0x16,0x27,0x1b,0x2c,0xd8,0x30,0x42,0x94,0xb8,0xf5,0x24,0xd3,0xf6,0xe1,0x17,0xa9,0x89,0x97,0xc0,0x69,0x30,0x92,0x6e,0xc0,0xf1,0xfa,0x55,0x78,0x69,0x09,0x03,0xa1,0x65,0x01};

unsigned char hdr_1[34] = {0x0e,0xbd,0x92,0x81,0x93,0x3a,0xaf,0x14,0x3b,0xe2,0x84,0xd8,0xc7,0xee,0x3d,0x56,0x31,0x9a,0x53,0x43,0x5f,0xdd,0xbd,0x35,0xd0,0x21,0xa9,0xec,0xb6,0x3f,0xd1,0x3d,0xb6,0x01};
unsigned char *param ="type a\nq 3473762690060260262939436651700804477367522263315046244003202311167126808821819\nh 60\nr 57896044834337671048990610861680074622792037721917437400053371852785446813697\nexp2 255\nexp1 227\nsign1 1\nsign0 1\n";
//*/


#if USE_COMPRESS
void set_element_binary_G1(element_t e, unsigned char *data,bkem_global_params_t gps)
{
print_timestamp();	printf("-----------------------decompression 1\n");
	element_init_G1(e, gps->pairing);
//	for(i=0;i<e->field->fixed_length_in_bytes;i++) 		printf("%02x",data[i]); 	printf("};\n");
	element_from_bytes_compressed(e,data);
//	e->field->from_bytes(e,data);
print_timestamp();	printf("-----------------------decompression 2\n");
}

#else
void set_element_binary_G1(element_t e, unsigned char *data,bkem_global_params_t gps)
{
	element_init_G1(e, gps->pairing);
//	for(i=0;i<e->field->fixed_length_in_bytes;i++) 		printf("%02x",data[i]); 	printf("};\n");
	e->field->from_bytes(e,data);
}
#endif
void set_element_binary_GT(element_t e, unsigned char *data,bkem_global_params_t gps)
{
	element_init_GT(e, gps->pairing);
//	for(i=0;i<e->field->fixed_length_in_bytes;i++) 		printf("%02x",data[i]);  	printf("};\n");
	e->field->from_bytes(e,data);
}


void set_pre_distributed_keys(bkem_system_t sys, bkem_global_params_t gps)
{
#if DUMP_MODE
	//printf(RED "DUMPING KEYS IN PROGRESS...\n" DEFAULT);
#else
	//set pre-processed keys from dumped variables.
	set_element_binary_G1(sys->PK->g,pk_g,gps);
	dump_element_binary2("pk_g",sys->PK->g);

	set_element_binary_G1(sys->PK->g_i[0],pk_g_0,gps);
//	dump_element_binary("pk_g_0",sys->PK->g_i[0]);

	set_element_binary_G1(sys->PK->g_i[1],pk_g_1,gps);
//	dump_element_binary("pk_g_1",sys->PK->g_i[1]);

	set_element_binary_G1(sys->PK->g_i[2],pk_g_2,gps);
//	dump_element_binary("pk_g_2",sys->PK->g_i[2]);

	set_element_binary_G1(sys->PK->g_i[3],pk_g_3,gps);
//	dump_element_binary("pk_g_3",sys->PK->g_i[3]);

	set_element_binary_G1(sys->PK->g_i[4],pk_g_4,gps);
//	dump_element_binary("pk_g_4",sys->PK->g_i[4]);

	set_element_binary_G1(sys->PK->g_i[5],pk_g_5,gps);
//	dump_element_binary("pk_g_5",sys->PK->g_i[5]);

	set_element_binary_G1(sys->PK->v_i[0],pk_v_0,gps);
//	dump_element_binary("pk_v_0",sys->PK->v_i[0]);

	set_element_binary_G1(sys->d_i[0],pr_0,gps);
//	dump_element_binary("pr_0",sys->d_i[0]);

	set_element_binary_G1(sys->d_i[1],pr_1,gps);
//	dump_element_binary("pr_1",sys->d_i[1]);

	set_element_binary_G1(sys->d_i[2],pr_2,gps);
//	dump_element_binary("pr_2",sys->d_i[2]);
#endif	
}

// g, h in some group of order r
// finds x such that g^x = h
// will hang if no such x exists
// x in some field_t that set_mpz makes sense for
#define SIGNATURE 0x12

void find_binary_match(element_t x, element_t g, element_t h)
{
  element_t g0,target,tt;
  mpz_t count, binary, product,temp,temp2;

  mpz_init(count);
  mpz_init(binary);
  mpz_init(product);
  mpz_init(temp);
  mpz_init(temp2);
//target binary from the curve
  mpz_set_ui(binary, SIGNATURE);
  element_init_same_as(target, g);
  element_init_same_as(tt, g);
//  element_set_mpz(target,binary);  
  element_set(target, g);
   dump_element_binary2("target0",target);
//  element_set_mpz(target, binary);

//  element_set_mpz(x, count);
  //our PK
  element_init_same_as(g0, g);
  element_set(g0, g);

  //^t to make the binary
  mpz_set_ui(count, 1);
//  while (element_cmp(target, h)) {
  while (1) {
   element_to_mpz(temp,g0); // get the mul value
   element_to_mpz(temp2,g0); // get the mul value

   element_set(target, g0);
//   element_set_mpz(target, temp2);
   dump_element_binary2("target1",target);
//  element_sub(target,target,target);
//  element_add_ui(target,target,0x1111);
   element_add(target,target,h);
   dump_element_binary2("target11",target);
   
   mpz_sub_ui(temp, temp,SIGNATURE);

   element_set_mpz(target, temp);
   dump_element_binary2("target2",target);
   
   mpz_sub(temp2, temp2,temp); // to make signature.

   element_set_mpz(target, temp2);
   dump_element_binary2("target3",target);

   element_set_mpz(target, temp2);
   dump_element_binary2("target4",target);
	
   if( mpz_cmp_ui(temp2,SIGNATURE)) {
   	//not match;
   	printf("NOT MATCH!!!!!!!!!!!!!!! \n");
	dump_element_binary2("value",g0);
   }
   else //match
   	{
   	printf("MATCH!!!!!!!!!!!!!!! \n");
	dump_element_binary2("value",g0);
	break;
   	}
      
   element_mul(g0, g0, g);
//element_printf("g0^%Zd = %B\n", count, g0);
    mpz_add_ui(count, count, 1);
  }
  
  element_set_mpz(x, count);
  mpz_clear(count);
  element_clear(g0);
}

void get_encryption_key2(keypair_t *key, int *S, int num_recip, bkem_system_t sys, bkem_global_params_t gps) {
	keypair_t kp;
	kp = pbc_malloc(sizeof(struct keypair_s));

	// Init header, g^t , A instances
	kp->HDR = pbc_malloc((gps->A + 1) * sizeof(element_t));

#if DUMP_MODE
	// Get random t
	element_t t;
	element_init_Zr(t, gps->pairing);
	element_random(t);

	dump_element_binary2("t",t);
	//	dump_element("sys->PK->g_i[gps->B-1]",sys->PK->g_i[gps->B-1]);
	//	dump_element("sys->PK->g_i[0]",sys->PK->g_i[0]);

#if 1
//	mpz_t v;
//	mpz_init_set_str(v,"1278",16);

//	element_t ct,temp,K2,K_TEMP;
//	element_init_GT(K2, gps->pairing);
//	element_init_Zr(K_TEMP, gps->pairing);

//	element_set_mpz(t,v);
//	dump_element_binary2("t",t);
	
//	element_init_Zr(ct, gps->pairing);
//	element_set_mpz(ct,v);
//	dump_element_binary2("ct",ct);	
	
	// Compute K = e(g_B, g_0)^t
//	element_init_GT(kp->K, gps->pairing);
//	dump_element_binary2("enc0",kp->K);
//	pairing_apply(K2, sys->PK->g_i[gps->B-1], sys->PK->g_i[0], gps->pairing);
//	element_pow_zn(kp->K, K2, t);

//	int n,n2,n3;
//	int n = element_length_in_bytes(kp->K);
//	int n2 = element_length_in_bytes_compressed(kp->K);

//	printf("n=%d,n2=%d\n",n,n2);
#else
	element_t ct,temp,K2;
	mpz_t v;
	element_init_GT(kp->K2, gps->pairing);
	mpz_init_set_str(v,"12345678",16);
	
	element_init_Zr(ct, gps->pairing);
	element_set_mpz(ct,v);
	dump_element_binary2("ct",ct);	
	
	// Compute K = e(g_B, g_0)^t
	element_init_GT(kp->K, gps->pairing);
//	dump_element_binary2("enc0",kp->K);
	pairing_apply(kp->K2, sys->PK->g_i[gps->B-1], sys->PK->g_i[0], gps->pairing);
	dump_element_binary2("enc1",kp->K2);
	element_pow_zn(kp->K, kp->K2, t);

	dump_element_binary2("enc2",kp->K);

#endif
	// Compute K = e(g_B, g_0)^t
	element_init_GT(kp->K, gps->pairing);
	pairing_apply(kp->K, sys->PK->g_i[gps->B-1], sys->PK->g_i[0], gps->pairing);
	element_pow_zn(kp->K, kp->K, t);
	dump_element_binary2("K",kp->K);
	// Set first header element to g^t
	element_init_G1(kp->HDR[0], gps->pairing);
	element_pow_zn(kp->HDR[0], sys->PK->g, t);

	dump_element_binary("hdr_0",kp->HDR[0]);

	// Init HDR 1-A with v_i
	int i;
	for (i = 1; i <= gps->A; ++i) {
		element_init_G1(kp->HDR[i], gps->pairing);
		element_set(kp->HDR[i], sys->PK->v_i[i-1]);
			//printf("E0 %d \n",i);
	}
	// Define Subsets
	int line, pos;
	for (i = 0; i < num_recip; ++i) {
	if (S[i] < 0 || S[i] >= gps->N) {
		printf("Element %d of receivers out of range\n", i);
		return;
	}
//	printf("E1 %d \n",i);
		// Get relative position of member S[i] within its subset
		// Determine position in HDR (+1 offset from first element)
		line = (int) (S[i] / gps->B);
		// Determine position
		pos = (S[i] % gps->B);
		element_mul(kp->HDR[line + 1], kp->HDR[line + 1], sys->PK->g_i[gps->B - 1 - pos]);
	}

	// Pow each subinstance with t
	for (i = 1; i <= gps->A; ++i) {
		char buf[32];
		sprintf(buf,"hdr_%d",i);
	//		printf("E2 %d \n",i);
		element_pow_zn(kp->HDR[i], kp->HDR[i], t);
		dump_element_binary(buf,kp->HDR[i]);
	}

	*key = kp;
	element_clear(t);
#else
	printf("RED""Encryption keys are loaded from pre-distributed values\n"DEFAULT);
	set_element_binary_GT(kp->K ,K ,gps); // for checking purpose
	set_element_binary_G1(kp->HDR[0],hdr_0,gps);
	set_element_binary_G1(kp->HDR[1],hdr_1,gps);
	*key = kp;
#endif
}


void setup2(bkem_system_t *sys, bkem_global_params_t gps) {
	// init key encapsulation system

    bkem_system_t gbs;
    gbs = pbc_malloc(sizeof(struct bkem_system_s));
    gbs->PK = pbc_malloc(sizeof(struct pubkey_s));
#if DUMP_MODE
	// Choose random generator
	element_init_G1(gbs->PK->g, gps->pairing);
	element_random(gbs->PK->g);
	dump_element_binary("pk_g",gbs->PK->g);
		// random alpha Zn
	element_t alpha;
	element_init_Zr(alpha, gps->pairing);
	element_random(alpha);
	
#else
#endif

	// Compute g_i's
	gbs->PK->g_i = pbc_malloc(2 * gps->B * sizeof(element_t));

#if DUMP_MODE
	// Set the first element to g^(alpha^1)
	element_init_G1(gbs->PK->g_i[0], gps->pairing);
	element_pow_zn(gbs->PK->g_i[0],gbs->PK->g, alpha);
	dump_element_binary("pk_g_0",gbs->PK->g_i[0]);
#else
#endif

	int i;
	for(i = 1; i < 2*gps->B; i++) {
#if DUMP_MODE
		char buf[32];
		sprintf(buf,"pk_g_%d",i);
	// g_(i+1) = g_i ^ alpha = (g^(alpha^i))^alpha
		element_init_G1(gbs->PK->g_i[i], gps->pairing);
		element_pow_zn(gbs->PK->g_i[i], gbs->PK->g_i[i-1], alpha);
		dump_element_binary(buf,gbs->PK->g_i[i]);
#else
#endif
	}

	// Choose random gamma_i and set v_i
	element_t *gamma_i;
	gamma_i = pbc_malloc(gps->A * sizeof(struct element_s));
	gbs->PK->v_i = pbc_malloc(gps->A * sizeof(struct element_s));
	for (i = 0; i < gps->A; i++) {
#if DUMP_MODE
		char buf[32];
		sprintf(buf,"pk_v_%d",i);
		element_init_Zr(gamma_i[i], gps->pairing);
		element_init_G1(gbs->PK->v_i[i], gps->pairing);
		element_random(gamma_i[i]);
		element_pow_zn(gbs->PK->v_i[i], gbs->PK->g, gamma_i[i]);
		dump_element_binary(buf,gbs->PK->v_i[i]);
#endif		
	}

	// Compute private keys d_i
	gbs->d_i = pbc_malloc(gps->N * sizeof(struct element_s));
	for (i = 0; i < gps->N; i++) {
#if DUMP_MODE
		char buf[32];
		sprintf(buf,"pr_%d",i);
		int a = (int) i / gps->B;
		int b = (int) i % gps->B;

		element_init_G1(gbs->d_i[i], gps->pairing);
		element_pow_zn(gbs->d_i[i], gbs->PK->g_i[b], gamma_i[a]);
		dump_element_binary(buf,gbs->d_i[i]);
#endif		
	}

	*sys = gbs;

#if DUMP_MODE	
	element_clear(alpha);
	for (i = 0; i < gps->A; ++i) {
		element_clear(gamma_i[i]);
	}
#endif
}

void get_decryption_key_pre(element_t K, bkem_global_params_t gps, int *S, int num_recip, int index,
        element_t d_i, element_t *HDR, pubkey_t PK) {

    // a is equal to instance
    int a = (int) (index / gps->B);

    // b is relative position in subset
    int b = index % gps->B;
	print_timestamp();	printf("get_decryption_key_pre----------------------- 1\n");
    element_t nom, den, temp;
    element_init_GT(nom, gps->pairing);
    // Set nominator to e(g_b, HDR_a) (+1 offset)

    pairing_apply(nom, PK->g_i[b], HDR[a + 1], gps->pairing);
	
//dump_element("PK->g_i[b]",PK->g_i[b]);
//dump_element("HDR[a + 1]",HDR[a + 1]);
//dump_element("d_i",d_i);
//dump_element_binary("nom_",nom);

    element_init_same_as(temp, d_i);
    element_set(temp, d_i);
//    dump_element_binary("temp",temp);

    int i, line, pos, pkpos;
    for (i = 0; i < num_recip; ++i) {
        if (S[i] < 0 || S[i] > gps->N) {
            printf("Element %d of receivers out of range\n", i);
            return;
        }

        // Get relative position of member S[i] within its subset
        line = (int) (S[i] / gps->B);
        // Determine position
        pos = (int) S[i] % gps->B;
	//printf("line = %d pos = %d \n",line,pos);

        if (line == a && pos != b) {
            pkpos = (gps->B) - pos+b;
	//	printf("pkpos=%d\n",pkpos);
//		dump_element_binary("PK->g_i[pkpos]",PK->g_i[pkpos]);
            element_mul(temp, temp, PK->g_i[pkpos]);
//		dump_element_binary("temp_mul",temp);
        }
    }
print_timestamp();	printf("get_decryption_key_pre----------------------- 2\n");
    element_init_GT(den, gps->pairing);
    pairing_apply(den, temp, HDR[0], gps->pairing);
//	dump_element_binary("den",den);

    element_init_GT(K, gps->pairing);
    element_div(K, nom, den);
print_timestamp();	printf("get_decryption_key_pre----------------------- 4\n");
//	dump_element_binary("K",K);
	
    element_clear(temp);
    element_clear(nom);
    element_clear(den);

}

#include <leds.h>
void pbc_extract_ciphertext()
{
	char buf[300];
	//fread(buf, 1, 4096, param);
	memcpy(buf,param,strlen(param));

	//	printf("\nSystem setup Key len = %d \n\n",strlen(buf));
	leds_on(LEDS_RED);
	print_timestamp();
	bkem_global_params_t gps;
	setup_global_system(&gps, (const char*) buf, 3);
	printf("param = [%s] \n",buf);

	printf("Global System parameters: N = %d, A = %d, B = %d\n\n", gps->N, gps->A, gps->B);
	bkem_system_t sys;
	setup2(&sys, gps);
	set_pre_distributed_keys(sys, gps);

	printf("\nTesting system\n\n");

	unsigned int c,k,j,i;
	for (c = 2; c <= gps->N; c*=2) {

	if (c >= 3) return;
	int S[c];
	printf("\nTesting targets with S = [ ");
	for (k = 0; k < c; ++k) {
		S[k] = k;
		printf("%d ", k);
	}

	printf("]\n\n");
	keypair_t keypair;
	get_encryption_key2(&keypair, S, c, sys, gps);
#if 0 // for  checking purposes
	for(i=0;i<c;i++)
		printf("S[%d] = %d\n",i,S[i]);
	
	dump_element("enc", keypair->K);
	dump_element("pk_g", sys->PK->g);	
	for (i = 0; i < 2 * gps->B; ++i) {
		sprintf(buf,"pk_g_%d",i);
		dump_element(buf,sys->PK->g_i[i]);
	}

	for (i = 0; i < gps->A; ++i) {
		sprintf(buf,"pk_v_%d",i);
		dump_element(buf,sys->PK->v_i[i]);
	}
	
	for(j=0;j<gps->N;j++)
	{
		sprintf(buf,"pr_%d",j);
		dump_element(buf,sys->d_i[j]);
	}
	for(i=0;i<=gps->A;i++)
	{
		sprintf(buf,"hdr_%d",i);
		dump_element(buf, keypair->HDR[i]);
	}
#endif
	element_t K;
	leds_off(LEDS_RED);
//	for (j = 0; j < gps->N; ++j) {
	for (j = 0; j < 1; j++) {
//		printf("c= %d, j= %d \n",c,j);
			sprintf(buf,"For Private key[%d]",j);
			dump_element_binary2(buf,sys->d_i[j]);
			get_decryption_key_pre(K, gps, S, c, j, sys->d_i[j], keypair->HDR, sys->PK);
			dump_element_binary2(RED"decryption key"DEFAULT, K);

		if (!element_cmp(keypair->K, K)) {
			if (j >= c)
				printf("ERROR: Decryption Key for [User %d] matches, but should NOT\n", j);       
		} else {
		if (j < c)
			printf("ERROR: Decryption Key for [User %d] does not match!\n", j);
		}
		element_clear(K);
		}
		free(keypair);
	}
	leds_on(LEDS_RED);
	print_timestamp();
}

#endif


/*
 * General construction of the
 * Boneh-Gentry-Waters broadcast key encapsulation scheme
 *
 * BKEM is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * BKEM is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with BKEM.  If not, see <http://www.gnu.org/licenses/>.
 *
 * Oliver Guenther
 * mail@oliverguenther.de
 *
 *
 * BKEM.c
 */

#if MINI_GMP
#include <string.h>
#include <stdio.h>
#include <math.h>


//#include<mini-gmp.h>
/////////////////////////////////////////////////////////////////////////////MINI GMP////////////////////////////////////////
//#include"mini-gmp.h"
/* mini-gmp, a minimalistic implementation of a GNU GMP subset.

   Contributed to the GNU project by Niels Möller

Copyright 1991-1997, 1999-2014 Free Software Foundation, Inc.

This file is part of the GNU MP Library.

The GNU MP Library is free software; you can redistribute it and/or modify
it under the terms of either:

  * the GNU Lesser General Public License as published by the Free
    Software Foundation; either version 3 of the License, or (at your
    option) any later version.

or

  * the GNU General Public License as published by the Free Software
    Foundation; either version 2 of the License, or (at your option) any
    later version.

or both in parallel, as here.

The GNU MP Library is distributed in the hope that it will be useful, but
WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
for more details.

You should have received copies of the GNU General Public License and the
GNU Lesser General Public License along with the GNU MP Library.  If not,
see https://www.gnu.org/licenses/.  */

/* NOTE: All functions in this file which are not declared in
   mini-gmp.h are internal, and are not intended to be compatible
   neither with GMP nor with future versions of mini-gmp. */

/* Much of the material copied from GMP files, including: gmp-impl.h,
   longlong.h, mpn/generic/add_n.c, mpn/generic/addmul_1.c,
   mpn/generic/lshift.c, mpn/generic/mul_1.c,
   mpn/generic/mul_basecase.c, mpn/generic/rshift.c,
   mpn/generic/sbpi1_div_qr.c, mpn/generic/sub_n.c,
   mpn/generic/submul_1.c. */

#include <assert.h>
#include <ctype.h>
#include <limits.h>
//#include <stdio.h>
#include <stdlib.h>
//#include <string.h>

#include <gmp.h>


/* Macros */
#define GMP_LIMB_BITS (sizeof(mp_limb_t) * CHAR_BIT)

#define GMP_LIMB_MAX (~ (mp_limb_t) 0)
#define GMP_LIMB_HIGHBIT ((mp_limb_t) 1 << (GMP_LIMB_BITS - 1))

#define GMP_HLIMB_BIT ((mp_limb_t) 1 << (GMP_LIMB_BITS / 2))
#define GMP_LLIMB_MASK (GMP_HLIMB_BIT - 1)

#define GMP_ULONG_BITS (sizeof(unsigned long) * CHAR_BIT)
#define GMP_ULONG_HIGHBIT ((unsigned long) 1 << (GMP_ULONG_BITS - 1))

#define GMP_ABS(x) ((x) >= 0 ? (x) : -(x))
#define GMP_NEG_CAST(T,x) (-((T)((x) + 1) - 1))

#define GMP_MIN(a, b) ((a) < (b) ? (a) : (b))
#define GMP_MAX(a, b) ((a) > (b) ? (a) : (b))

#define gmp_assert_nocarry(x) do { \
    mp_limb_t __cy = x;		   \
    assert (__cy == 0);		   \
  } while (0)

#define gmp_clz(count, x) do {						\
    mp_limb_t __clz_x = (x);						\
    unsigned __clz_c;							\
    for (__clz_c = 0;							\
	 (__clz_x & ((mp_limb_t) 0xff << (GMP_LIMB_BITS - 8))) == 0;	\
	 __clz_c += 8)							\
      __clz_x <<= 8;							\
    for (; (__clz_x & GMP_LIMB_HIGHBIT) == 0; __clz_c++)		\
      __clz_x <<= 1;							\
    (count) = __clz_c;							\
  } while (0)

#define gmp_ctz(count, x) do {						\
    mp_limb_t __ctz_x = (x);						\
    unsigned __ctz_c = 0;						\
    gmp_clz (__ctz_c, __ctz_x & - __ctz_x);				\
    (count) = GMP_LIMB_BITS - 1 - __ctz_c;				\
  } while (0)

#define gmp_add_ssaaaa(sh, sl, ah, al, bh, bl) \
  do {									\
    mp_limb_t __x;							\
    __x = (al) + (bl);							\
    (sh) = (ah) + (bh) + (__x < (al));					\
    (sl) = __x;								\
  } while (0)

#define gmp_sub_ddmmss(sh, sl, ah, al, bh, bl) \
  do {									\
    mp_limb_t __x;							\
    __x = (al) - (bl);							\
    (sh) = (ah) - (bh) - ((al) < (bl));					\
    (sl) = __x;								\
  } while (0)

#define gmp_umul_ppmm(w1, w0, u, v)					\
  do {									\
    mp_limb_t __x0, __x1, __x2, __x3;					\
    unsigned __ul, __vl, __uh, __vh;					\
    mp_limb_t __u = (u), __v = (v);					\
									\
    __ul = __u & GMP_LLIMB_MASK;					\
    __uh = __u >> (GMP_LIMB_BITS / 2);					\
    __vl = __v & GMP_LLIMB_MASK;					\
    __vh = __v >> (GMP_LIMB_BITS / 2);					\
									\
    __x0 = (mp_limb_t) __ul * __vl;					\
    __x1 = (mp_limb_t) __ul * __vh;					\
    __x2 = (mp_limb_t) __uh * __vl;					\
    __x3 = (mp_limb_t) __uh * __vh;					\
									\
    __x1 += __x0 >> (GMP_LIMB_BITS / 2);/* this can't give carry */	\
    __x1 += __x2;		/* but this indeed can */		\
    if (__x1 < __x2)		/* did we get it? */			\
      __x3 += GMP_HLIMB_BIT;	/* yes, add it in the proper pos. */	\
									\
    (w1) = __x3 + (__x1 >> (GMP_LIMB_BITS / 2));			\
    (w0) = (__x1 << (GMP_LIMB_BITS / 2)) + (__x0 & GMP_LLIMB_MASK);	\
  } while (0)

#define gmp_udiv_qrnnd_preinv(q, r, nh, nl, d, di)			\
  do {									\
    mp_limb_t _qh, _ql, _r, _mask;					\
    gmp_umul_ppmm (_qh, _ql, (nh), (di));				\
    gmp_add_ssaaaa (_qh, _ql, _qh, _ql, (nh) + 1, (nl));		\
    _r = (nl) - _qh * (d);						\
    _mask = -(mp_limb_t) (_r > _ql); /* both > and >= are OK */		\
    _qh += _mask;							\
    _r += _mask & (d);							\
    if (_r >= (d))							\
      {									\
	_r -= (d);							\
	_qh++;								\
      }									\
									\
    (r) = _r;								\
    (q) = _qh;								\
  } while (0)

#define gmp_udiv_qr_3by2(q, r1, r0, n2, n1, n0, d1, d0, dinv)		\
  do {									\
    mp_limb_t _q0, _t1, _t0, _mask;					\
    gmp_umul_ppmm ((q), _q0, (n2), (dinv));				\
    gmp_add_ssaaaa ((q), _q0, (q), _q0, (n2), (n1));			\
									\
    /* Compute the two most significant limbs of n - q'd */		\
    (r1) = (n1) - (d1) * (q);						\
    gmp_sub_ddmmss ((r1), (r0), (r1), (n0), (d1), (d0));		\
    gmp_umul_ppmm (_t1, _t0, (d0), (q));				\
    gmp_sub_ddmmss ((r1), (r0), (r1), (r0), _t1, _t0);			\
    (q)++;								\
									\
    /* Conditionally adjust q and the remainders */			\
    _mask = - (mp_limb_t) ((r1) >= _q0);				\
    (q) += _mask;							\
    gmp_add_ssaaaa ((r1), (r0), (r1), (r0), _mask & (d1), _mask & (d0)); \
    if ((r1) >= (d1))							\
      {									\
	if ((r1) > (d1) || (r0) >= (d0))				\
	  {								\
	    (q)++;							\
	    gmp_sub_ddmmss ((r1), (r0), (r1), (r0), (d1), (d0));	\
	  }								\
      }									\
  } while (0)

/* Swap macros. */
#define MP_LIMB_T_SWAP(x, y)						\
  do {									\
    mp_limb_t __mp_limb_t_swap__tmp = (x);				\
    (x) = (y);								\
    (y) = __mp_limb_t_swap__tmp;					\
  } while (0)
#define MP_SIZE_T_SWAP(x, y)						\
  do {									\
    mp_size_t __mp_size_t_swap__tmp = (x);				\
    (x) = (y);								\
    (y) = __mp_size_t_swap__tmp;					\
  } while (0)
#define MP_BITCNT_T_SWAP(x,y)			\
  do {						\
    mp_bitcnt_t __mp_bitcnt_t_swap__tmp = (x);	\
    (x) = (y);					\
    (y) = __mp_bitcnt_t_swap__tmp;		\
  } while (0)
#define MP_PTR_SWAP(x, y)						\
  do {									\
    mp_ptr __mp_ptr_swap__tmp = (x);					\
    (x) = (y);								\
    (y) = __mp_ptr_swap__tmp;						\
  } while (0)
#define MP_SRCPTR_SWAP(x, y)						\
  do {									\
    mp_srcptr __mp_srcptr_swap__tmp = (x);				\
    (x) = (y);								\
    (y) = __mp_srcptr_swap__tmp;					\
  } while (0)

#define MPN_PTR_SWAP(xp,xs, yp,ys)					\
  do {									\
    MP_PTR_SWAP (xp, yp);						\
    MP_SIZE_T_SWAP (xs, ys);						\
  } while(0)
#define MPN_SRCPTR_SWAP(xp,xs, yp,ys)					\
  do {									\
    MP_SRCPTR_SWAP (xp, yp);						\
    MP_SIZE_T_SWAP (xs, ys);						\
  } while(0)

#define MPZ_PTR_SWAP(x, y)						\
  do {									\
    mpz_ptr __mpz_ptr_swap__tmp = (x);					\
    (x) = (y);								\
    (y) = __mpz_ptr_swap__tmp;						\
  } while (0)
#define MPZ_SRCPTR_SWAP(x, y)						\
  do {									\
    mpz_srcptr __mpz_srcptr_swap__tmp = (x);				\
    (x) = (y);								\
    (y) = __mpz_srcptr_swap__tmp;					\
  } while (0)

const int mp_bits_per_limb = GMP_LIMB_BITS;


/* Memory allocation and other helper functions. */
static void
gmp_die (const char *msg)
{
printf("gmp_die %s!!!!!!!!!!!\n",msg);
  fprintf (stderr, "%s\n", msg);
  abort();
}

static void *
gmp_default_alloc (size_t size)
{
  void *p;

  assert (size > 0);
//printf("gmp_default_alloc size = %d\n",size);
  p = malloc (size);
  if (!p)
    gmp_die("gmp_default_alloc: Virtual memory exhausted.");

  return p;
}

static void *
gmp_default_realloc (void *old, size_t old_size, size_t new_size)
{
  mp_ptr p;
//printf("gmp_default_realloc size = %d\n",new_size);
  p = realloc (old, new_size);

  if (!p)
    gmp_die("gmp_default_realoc: Virtual memory exhausted.");

  return p;
}

static void
gmp_default_free (void *p, size_t size)
{
  free (p);
}

static void * (*gmp_allocate_func) (size_t) = gmp_default_alloc;
static void * (*gmp_reallocate_func) (void *, size_t, size_t) = gmp_default_realloc;
static void (*gmp_free_func) (void *, size_t) = gmp_default_free;

void
mp_get_memory_functions (void *(**alloc_func) (size_t),
			 void *(**realloc_func) (void *, size_t, size_t),
			 void (**free_func) (void *, size_t))
{
  if (alloc_func)
    *alloc_func = gmp_allocate_func;

  if (realloc_func)
    *realloc_func = gmp_reallocate_func;

  if (free_func)
    *free_func = gmp_free_func;
}

void
mp_set_memory_functions (void *(*alloc_func) (size_t),
			 void *(*realloc_func) (void *, size_t, size_t),
			 void (*free_func) (void *, size_t))
{
  if (!alloc_func)
    alloc_func = gmp_default_alloc;
  if (!realloc_func)
    realloc_func = gmp_default_realloc;
  if (!free_func)
    free_func = gmp_default_free;

  gmp_allocate_func = alloc_func;
  gmp_reallocate_func = realloc_func;
  gmp_free_func = free_func;
}

#define gmp_xalloc(size) ((*gmp_allocate_func)((size)))
#define gmp_free(p) ((*gmp_free_func) ((p), 0))

static mp_ptr
gmp_xalloc_limbs (mp_size_t size)
{
  return gmp_xalloc (size * sizeof (mp_limb_t));
}

static mp_ptr
gmp_xrealloc_limbs (mp_ptr old, mp_size_t size)
{
  assert (size > 0);
  return (*gmp_reallocate_func) (old, 0, size * sizeof (mp_limb_t));
}


/* MPN interface */

void
mpn_copyi (mp_ptr d, mp_srcptr s, mp_size_t n)
{
  mp_size_t i;
  for (i = 0; i < n; i++)
    d[i] = s[i];
}

void
mpn_copyd (mp_ptr d, mp_srcptr s, mp_size_t n)
{
  while (n-- > 0)
    d[n] = s[n];
}

int
mpn_cmp (mp_srcptr ap, mp_srcptr bp, mp_size_t n)
{
  while (--n >= 0)
    {
      if (ap[n] != bp[n])
	return ap[n] > bp[n] ? 1 : -1;
    }
  return 0;
}

static int
mpn_cmp4 (mp_srcptr ap, mp_size_t an, mp_srcptr bp, mp_size_t bn)
{
  if (an != bn)
    return an < bn ? -1 : 1;
  else
    return mpn_cmp (ap, bp, an);
}

static mp_size_t
mpn_normalized_size (mp_srcptr xp, mp_size_t n)
{
  for (; n > 0 && xp[n-1] == 0; n--)
    ;
  return n;
}

#define mpn_zero_p(xp, n) (mpn_normalized_size ((xp), (n)) == 0)

void
mpn_zero (mp_ptr rp, mp_size_t n)
{
  mp_size_t i;

  for (i = 0; i < n; i++)
    rp[i] = 0;
}

mp_limb_t
mpn_add_1 (mp_ptr rp, mp_srcptr ap, mp_size_t n, mp_limb_t b)
{
  mp_size_t i;

  assert (n > 0);
  i = 0;
  do
    {
      mp_limb_t r = ap[i] + b;
      /* Carry out */
      b = (r < b);
      rp[i] = r;
    }
  while (++i < n);

  return b;
}

mp_limb_t
mpn_add_n (mp_ptr rp, mp_srcptr ap, mp_srcptr bp, mp_size_t n)
{
  mp_size_t i;
  mp_limb_t cy;

  for (i = 0, cy = 0; i < n; i++)
    {
      mp_limb_t a, b, r;
      a = ap[i]; b = bp[i];
      r = a + cy;
      cy = (r < cy);
      r += b;
      cy += (r < b);
      rp[i] = r;
    }
  return cy;
}

mp_limb_t
mpn_add (mp_ptr rp, mp_srcptr ap, mp_size_t an, mp_srcptr bp, mp_size_t bn)
{
  mp_limb_t cy;

  assert (an >= bn);

  cy = mpn_add_n (rp, ap, bp, bn);
  if (an > bn)
    cy = mpn_add_1 (rp + bn, ap + bn, an - bn, cy);
  return cy;
}

mp_limb_t
mpn_sub_1 (mp_ptr rp, mp_srcptr ap, mp_size_t n, mp_limb_t b)
{
  mp_size_t i;

  assert (n > 0);

  i = 0;
  do
    {
      mp_limb_t a = ap[i];
      /* Carry out */
      mp_limb_t cy = a < b;;
      rp[i] = a - b;
      b = cy;
    }
  while (++i < n);

  return b;
}

mp_limb_t
mpn_sub_n (mp_ptr rp, mp_srcptr ap, mp_srcptr bp, mp_size_t n)
{
  mp_size_t i;
  mp_limb_t cy;

  for (i = 0, cy = 0; i < n; i++)
    {
      mp_limb_t a, b;
      a = ap[i]; b = bp[i];
      b += cy;
      cy = (b < cy);
      cy += (a < b);
      rp[i] = a - b;
    }
  return cy;
}

mp_limb_t
mpn_sub (mp_ptr rp, mp_srcptr ap, mp_size_t an, mp_srcptr bp, mp_size_t bn)
{
  mp_limb_t cy;

  assert (an >= bn);

  cy = mpn_sub_n (rp, ap, bp, bn);
  if (an > bn)
    cy = mpn_sub_1 (rp + bn, ap + bn, an - bn, cy);
  return cy;
}

mp_limb_t
mpn_mul_1 (mp_ptr rp, mp_srcptr up, mp_size_t n, mp_limb_t vl)
{
  mp_limb_t ul, cl, hpl, lpl;

  assert (n >= 1);

  cl = 0;
  do
    {
      ul = *up++;
      gmp_umul_ppmm (hpl, lpl, ul, vl);

      lpl += cl;
      cl = (lpl < cl) + hpl;

      *rp++ = lpl;
    }
  while (--n != 0);

  return cl;
}

mp_limb_t
mpn_addmul_1 (mp_ptr rp, mp_srcptr up, mp_size_t n, mp_limb_t vl)
{
  mp_limb_t ul, cl, hpl, lpl, rl;

  assert (n >= 1);

  cl = 0;
  do
    {
      ul = *up++;
      gmp_umul_ppmm (hpl, lpl, ul, vl);

      lpl += cl;
      cl = (lpl < cl) + hpl;

      rl = *rp;
      lpl = rl + lpl;
      cl += lpl < rl;
      *rp++ = lpl;
    }
  while (--n != 0);

  return cl;
}

mp_limb_t
mpn_submul_1 (mp_ptr rp, mp_srcptr up, mp_size_t n, mp_limb_t vl)
{
  mp_limb_t ul, cl, hpl, lpl, rl;

  assert (n >= 1);

  cl = 0;
  do
    {
      ul = *up++;
      gmp_umul_ppmm (hpl, lpl, ul, vl);

      lpl += cl;
      cl = (lpl < cl) + hpl;

      rl = *rp;
      lpl = rl - lpl;
      cl += lpl > rl;
      *rp++ = lpl;
    }
  while (--n != 0);

  return cl;
}

mp_limb_t
mpn_mul (mp_ptr rp, mp_srcptr up, mp_size_t un, mp_srcptr vp, mp_size_t vn)
{
  assert (un >= vn);
  assert (vn >= 1);

  /* We first multiply by the low order limb. This result can be
     stored, not added, to rp. We also avoid a loop for zeroing this
     way. */

  rp[un] = mpn_mul_1 (rp, up, un, vp[0]);
  rp += 1, vp += 1, vn -= 1;

  /* Now accumulate the product of up[] and the next higher limb from
     vp[]. */

  while (vn >= 1)
    {
      rp[un] = mpn_addmul_1 (rp, up, un, vp[0]);
      rp += 1, vp += 1, vn -= 1;
    }
  return rp[un - 1];
}

void
mpn_mul_n (mp_ptr rp, mp_srcptr ap, mp_srcptr bp, mp_size_t n)
{
  mpn_mul (rp, ap, n, bp, n);
}

void
mpn_sqr (mp_ptr rp, mp_srcptr ap, mp_size_t n)
{
  mpn_mul (rp, ap, n, ap, n);
}

mp_limb_t
mpn_lshift (mp_ptr rp, mp_srcptr up, mp_size_t n, unsigned int cnt)
{
  mp_limb_t high_limb, low_limb;
  unsigned int tnc;
  mp_size_t i;
  mp_limb_t retval;

  assert (n >= 1);
  assert (cnt >= 1);
  assert (cnt < GMP_LIMB_BITS);

  up += n;
  rp += n;

  tnc = GMP_LIMB_BITS - cnt;
  low_limb = *--up;
  retval = low_limb >> tnc;
  high_limb = (low_limb << cnt);

  for (i = n; --i != 0;)
    {
      low_limb = *--up;
      *--rp = high_limb | (low_limb >> tnc);
      high_limb = (low_limb << cnt);
    }
  *--rp = high_limb;

  return retval;
}

mp_limb_t
mpn_rshift (mp_ptr rp, mp_srcptr up, mp_size_t n, unsigned int cnt)
{
  mp_limb_t high_limb, low_limb;
  unsigned int tnc;
  mp_size_t i;
  mp_limb_t retval;

  assert (n >= 1);
  assert (cnt >= 1);
  assert (cnt < GMP_LIMB_BITS);

  tnc = GMP_LIMB_BITS - cnt;
  high_limb = *up++;
  retval = (high_limb << tnc);
  low_limb = high_limb >> cnt;

  for (i = n; --i != 0;)
    {
      high_limb = *up++;
      *rp++ = low_limb | (high_limb << tnc);
      low_limb = high_limb >> cnt;
    }
  *rp = low_limb;

  return retval;
}

static mp_bitcnt_t
mpn_common_scan (mp_limb_t limb, mp_size_t i, mp_srcptr up, mp_size_t un,
		 mp_limb_t ux)
{
  unsigned cnt;

  assert (ux == 0 || ux == GMP_LIMB_MAX);
  assert (0 <= i && i <= un );

  while (limb == 0)
    {
      i++;
      if (i == un)
	return (ux == 0 ? ~(mp_bitcnt_t) 0 : un * GMP_LIMB_BITS);
      limb = ux ^ up[i];
    }
  gmp_ctz (cnt, limb);
  return (mp_bitcnt_t) i * GMP_LIMB_BITS + cnt;
}

mp_bitcnt_t
mpn_scan1 (mp_srcptr ptr, mp_bitcnt_t bit)
{
  mp_size_t i;
  i = bit / GMP_LIMB_BITS;

  return mpn_common_scan ( ptr[i] & (GMP_LIMB_MAX << (bit % GMP_LIMB_BITS)),
			  i, ptr, i, 0);
}

mp_bitcnt_t
mpn_scan0 (mp_srcptr ptr, mp_bitcnt_t bit)
{
  mp_size_t i;
  i = bit / GMP_LIMB_BITS;

  return mpn_common_scan (~ptr[i] & (GMP_LIMB_MAX << (bit % GMP_LIMB_BITS)),
			  i, ptr, i, GMP_LIMB_MAX);
}


/* MPN division interface. */
mp_limb_t
mpn_invert_3by2 (mp_limb_t u1, mp_limb_t u0)
{
  mp_limb_t r, p, m;
  unsigned ul, uh;
  unsigned ql, qh;

  /* First, do a 2/1 inverse. */
  /* The inverse m is defined as floor( (B^2 - 1 - u1)/u1 ), so that 0 <
   * B^2 - (B + m) u1 <= u1 */
  assert (u1 >= GMP_LIMB_HIGHBIT);

  ul = u1 & GMP_LLIMB_MASK;
  uh = u1 >> (GMP_LIMB_BITS / 2);

  qh = ~u1 / uh;
  r = ((~u1 - (mp_limb_t) qh * uh) << (GMP_LIMB_BITS / 2)) | GMP_LLIMB_MASK;

  p = (mp_limb_t) qh * ul;
  /* Adjustment steps taken from udiv_qrnnd_c */
  if (r < p)
    {
      qh--;
      r += u1;
      if (r >= u1) /* i.e. we didn't get carry when adding to r */
	if (r < p)
	  {
	    qh--;
	    r += u1;
	  }
    }
  r -= p;

  /* Do a 3/2 division (with half limb size) */
  p = (r >> (GMP_LIMB_BITS / 2)) * qh + r;
  ql = (p >> (GMP_LIMB_BITS / 2)) + 1;

  /* By the 3/2 method, we don't need the high half limb. */
  r = (r << (GMP_LIMB_BITS / 2)) + GMP_LLIMB_MASK - ql * u1;

  if (r >= (p << (GMP_LIMB_BITS / 2)))
    {
      ql--;
      r += u1;
    }
  m = ((mp_limb_t) qh << (GMP_LIMB_BITS / 2)) + ql;
  if (r >= u1)
    {
      m++;
      r -= u1;
    }

  if (u0 > 0)
    {
      mp_limb_t th, tl;
      r = ~r;
      r += u0;
      if (r < u0)
	{
	  m--;
	  if (r >= u1)
	    {
	      m--;
	      r -= u1;
	    }
	  r -= u1;
	}
      gmp_umul_ppmm (th, tl, u0, m);
      r += th;
      if (r < th)
	{
	  m--;
	  m -= ((r > u1) | ((r == u1) & (tl > u0)));
	}
    }

  return m;
}

struct gmp_div_inverse
{
  /* Normalization shift count. */
  unsigned shift;
  /* Normalized divisor (d0 unused for mpn_div_qr_1) */
  mp_limb_t d1, d0;
  /* Inverse, for 2/1 or 3/2. */
  mp_limb_t di;
};

static void
mpn_div_qr_1_invert (struct gmp_div_inverse *inv, mp_limb_t d)
{
  unsigned shift;

  assert (d > 0);
  gmp_clz (shift, d);
  inv->shift = shift;
  inv->d1 = d << shift;
  inv->di = mpn_invert_limb (inv->d1);
}

static void
mpn_div_qr_2_invert (struct gmp_div_inverse *inv,
		     mp_limb_t d1, mp_limb_t d0)
{
  unsigned shift;

  assert (d1 > 0);
  gmp_clz (shift, d1);
  inv->shift = shift;
  if (shift > 0)
    {
      d1 = (d1 << shift) | (d0 >> (GMP_LIMB_BITS - shift));
      d0 <<= shift;
    }
  inv->d1 = d1;
  inv->d0 = d0;
  inv->di = mpn_invert_3by2 (d1, d0);
}

static void
mpn_div_qr_invert (struct gmp_div_inverse *inv,
		   mp_srcptr dp, mp_size_t dn)
{
  assert (dn > 0);

  if (dn == 1)
    mpn_div_qr_1_invert (inv, dp[0]);
  else if (dn == 2)
    mpn_div_qr_2_invert (inv, dp[1], dp[0]);
  else
    {
      unsigned shift;
      mp_limb_t d1, d0;

      d1 = dp[dn-1];
      d0 = dp[dn-2];
      assert (d1 > 0);
      gmp_clz (shift, d1);
      inv->shift = shift;
      if (shift > 0)
	{
	  d1 = (d1 << shift) | (d0 >> (GMP_LIMB_BITS - shift));
	  d0 = (d0 << shift) | (dp[dn-3] >> (GMP_LIMB_BITS - shift));
	}
      inv->d1 = d1;
      inv->d0 = d0;
      inv->di = mpn_invert_3by2 (d1, d0);
    }
}

/* Not matching current public gmp interface, rather corresponding to
   the sbpi1_div_* functions. */
static mp_limb_t
mpn_div_qr_1_preinv (mp_ptr qp, mp_srcptr np, mp_size_t nn,
		     const struct gmp_div_inverse *inv)
{
  mp_limb_t d, di;
  mp_limb_t r;
  mp_ptr tp = NULL;

  if (inv->shift > 0)
    {
      tp = gmp_xalloc_limbs (nn);
      r = mpn_lshift (tp, np, nn, inv->shift);
      np = tp;
    }
  else
    r = 0;

  d = inv->d1;
  di = inv->di;
  while (nn-- > 0)
    {
      mp_limb_t q;

      gmp_udiv_qrnnd_preinv (q, r, r, np[nn], d, di);
      if (qp)
	qp[nn] = q;
    }
  if (inv->shift > 0)
    gmp_free (tp);

  return r >> inv->shift;
}

static mp_limb_t
mpn_div_qr_1 (mp_ptr qp, mp_srcptr np, mp_size_t nn, mp_limb_t d)
{
  assert (d > 0);

  /* Special case for powers of two. */
  if ((d & (d-1)) == 0)
    {
      mp_limb_t r = np[0] & (d-1);
      if (qp)
	{
	  if (d <= 1)
	    mpn_copyi (qp, np, nn);
	  else
	    {
	      unsigned shift;
	      gmp_ctz (shift, d);
	      mpn_rshift (qp, np, nn, shift);
	    }
	}
      return r;
    }
  else
    {
      struct gmp_div_inverse inv;
      mpn_div_qr_1_invert (&inv, d);
      return mpn_div_qr_1_preinv (qp, np, nn, &inv);
    }
}

static void
mpn_div_qr_2_preinv (mp_ptr qp, mp_ptr rp, mp_srcptr np, mp_size_t nn,
		     const struct gmp_div_inverse *inv)
{
  unsigned shift;
  mp_size_t i;
  mp_limb_t d1, d0, di, r1, r0;
  mp_ptr tp;

  assert (nn >= 2);
  shift = inv->shift;
  d1 = inv->d1;
  d0 = inv->d0;
  di = inv->di;

  if (shift > 0)
    {
      tp = gmp_xalloc_limbs (nn);
      r1 = mpn_lshift (tp, np, nn, shift);
      np = tp;
    }
  else
    r1 = 0;

  r0 = np[nn - 1];

  i = nn - 2;
  do
    {
      mp_limb_t n0, q;
      n0 = np[i];
      gmp_udiv_qr_3by2 (q, r1, r0, r1, r0, n0, d1, d0, di);

      if (qp)
	qp[i] = q;
    }
  while (--i >= 0);

  if (shift > 0)
    {
      assert ((r0 << (GMP_LIMB_BITS - shift)) == 0);
      r0 = (r0 >> shift) | (r1 << (GMP_LIMB_BITS - shift));
      r1 >>= shift;

      gmp_free (tp);
    }

  rp[1] = r1;
  rp[0] = r0;
}

#if 0
static void
mpn_div_qr_2 (mp_ptr qp, mp_ptr rp, mp_srcptr np, mp_size_t nn,
	      mp_limb_t d1, mp_limb_t d0)
{
  struct gmp_div_inverse inv;
  assert (nn >= 2);

  mpn_div_qr_2_invert (&inv, d1, d0);
  mpn_div_qr_2_preinv (qp, rp, np, nn, &inv);
}
#endif

static void
mpn_div_qr_pi1 (mp_ptr qp,
		mp_ptr np, mp_size_t nn, mp_limb_t n1,
		mp_srcptr dp, mp_size_t dn,
		mp_limb_t dinv)
{
  mp_size_t i;

  mp_limb_t d1, d0;
  mp_limb_t cy, cy1;
  mp_limb_t q;

  assert (dn > 2);
  assert (nn >= dn);

  d1 = dp[dn - 1];
  d0 = dp[dn - 2];

  assert ((d1 & GMP_LIMB_HIGHBIT) != 0);
  /* Iteration variable is the index of the q limb.
   *
   * We divide <n1, np[dn-1+i], np[dn-2+i], np[dn-3+i],..., np[i]>
   * by            <d1,          d0,        dp[dn-3],  ..., dp[0] >
   */

  i = nn - dn;
  do
    {
      mp_limb_t n0 = np[dn-1+i];

      if (n1 == d1 && n0 == d0)
	{
	  q = GMP_LIMB_MAX;
	  mpn_submul_1 (np+i, dp, dn, q);
	  n1 = np[dn-1+i];	/* update n1, last loop's value will now be invalid */
	}
      else
	{
	  gmp_udiv_qr_3by2 (q, n1, n0, n1, n0, np[dn-2+i], d1, d0, dinv);

	  cy = mpn_submul_1 (np + i, dp, dn-2, q);

	  cy1 = n0 < cy;
	  n0 = n0 - cy;
	  cy = n1 < cy1;
	  n1 = n1 - cy1;
	  np[dn-2+i] = n0;

	  if (cy != 0)
	    {
	      n1 += d1 + mpn_add_n (np + i, np + i, dp, dn - 1);
	      q--;
	    }
	}

      if (qp)
	qp[i] = q;
    }
  while (--i >= 0);

  np[dn - 1] = n1;
}

static void
mpn_div_qr_preinv (mp_ptr qp, mp_ptr np, mp_size_t nn,
		   mp_srcptr dp, mp_size_t dn,
		   const struct gmp_div_inverse *inv)
{
  assert (dn > 0);
  assert (nn >= dn);

  if (dn == 1)
    np[0] = mpn_div_qr_1_preinv (qp, np, nn, inv);
  else if (dn == 2)
    mpn_div_qr_2_preinv (qp, np, np, nn, inv);
  else
    {
      mp_limb_t nh;
      unsigned shift;

      assert (inv->d1 == dp[dn-1]);
      assert (inv->d0 == dp[dn-2]);
      assert ((inv->d1 & GMP_LIMB_HIGHBIT) != 0);

      shift = inv->shift;
      if (shift > 0)
	nh = mpn_lshift (np, np, nn, shift);
      else
	nh = 0;

      mpn_div_qr_pi1 (qp, np, nn, nh, dp, dn, inv->di);

      if (shift > 0)
	gmp_assert_nocarry (mpn_rshift (np, np, dn, shift));
    }
}

static void
mpn_div_qr (mp_ptr qp, mp_ptr np, mp_size_t nn, mp_srcptr dp, mp_size_t dn)
{
  struct gmp_div_inverse inv;
  mp_ptr tp = NULL;

  assert (dn > 0);
  assert (nn >= dn);

  mpn_div_qr_invert (&inv, dp, dn);
  if (dn > 2 && inv.shift > 0)
    {
      tp = gmp_xalloc_limbs (dn);
      gmp_assert_nocarry (mpn_lshift (tp, dp, dn, inv.shift));
      dp = tp;
    }
  mpn_div_qr_preinv (qp, np, nn, dp, dn, &inv);
  if (tp)
    gmp_free (tp);
}


/* MPN base conversion. */
static unsigned
mpn_base_power_of_two_p (unsigned b)
{
  switch (b)
    {
    case 2: return 1;
    case 4: return 2;
    case 8: return 3;
    case 16: return 4;
    case 32: return 5;
    case 64: return 6;
    case 128: return 7;
    case 256: return 8;
    default: return 0;
    }
}

struct mpn_base_info
{
  /* bb is the largest power of the base which fits in one limb, and
     exp is the corresponding exponent. */
  unsigned exp;
  mp_limb_t bb;
};

static void
mpn_get_base_info (struct mpn_base_info *info, mp_limb_t b)
{
  mp_limb_t m;
  mp_limb_t p;
  unsigned exp;

  m = GMP_LIMB_MAX / b;
  for (exp = 1, p = b; p <= m; exp++)
    p *= b;

  info->exp = exp;
  info->bb = p;
}

static mp_bitcnt_t
mpn_limb_size_in_base_2 (mp_limb_t u)
{
  unsigned shift;

  assert (u > 0);
  gmp_clz (shift, u);
  return GMP_LIMB_BITS - shift;
}

static size_t
mpn_get_str_bits (unsigned char *sp, unsigned bits, mp_srcptr up, mp_size_t un)
{
  unsigned char mask;
  size_t sn, j;
  mp_size_t i;
  int shift;

  sn = ((un - 1) * GMP_LIMB_BITS + mpn_limb_size_in_base_2 (up[un-1])
	+ bits - 1) / bits;

  mask = (1U << bits) - 1;

  for (i = 0, j = sn, shift = 0; j-- > 0;)
    {
      unsigned char digit = up[i] >> shift;

      shift += bits;

      if (shift >= GMP_LIMB_BITS && ++i < un)
	{
	  shift -= GMP_LIMB_BITS;
	  digit |= up[i] << (bits - shift);
	}
      sp[j] = digit & mask;
    }
  return sn;
}

/* We generate digits from the least significant end, and reverse at
   the end. */
static size_t
mpn_limb_get_str (unsigned char *sp, mp_limb_t w,
		  const struct gmp_div_inverse *binv)
{
  mp_size_t i;
  for (i = 0; w > 0; i++)
    {
      mp_limb_t h, l, r;

      h = w >> (GMP_LIMB_BITS - binv->shift);
      l = w << binv->shift;

      gmp_udiv_qrnnd_preinv (w, r, h, l, binv->d1, binv->di);
      assert ( (r << (GMP_LIMB_BITS - binv->shift)) == 0);
      r >>= binv->shift;

      sp[i] = r;
    }
  return i;
}

static size_t
mpn_get_str_other (unsigned char *sp,
		   int base, const struct mpn_base_info *info,
		   mp_ptr up, mp_size_t un)
{
  struct gmp_div_inverse binv;
  size_t sn;
  size_t i;

  mpn_div_qr_1_invert (&binv, base);

  sn = 0;

  if (un > 1)
    {
      struct gmp_div_inverse bbinv;
      mpn_div_qr_1_invert (&bbinv, info->bb);

      do
	{
	  mp_limb_t w;
	  size_t done;
	  w = mpn_div_qr_1_preinv (up, up, un, &bbinv);
	  un -= (up[un-1] == 0);
	  done = mpn_limb_get_str (sp + sn, w, &binv);

	  for (sn += done; done < info->exp; done++)
	    sp[sn++] = 0;
	}
      while (un > 1);
    }
  sn += mpn_limb_get_str (sp + sn, up[0], &binv);

  /* Reverse order */
  for (i = 0; 2*i + 1 < sn; i++)
    {
      unsigned char t = sp[i];
      sp[i] = sp[sn - i - 1];
      sp[sn - i - 1] = t;
    }

  return sn;
}

size_t
mpn_get_str (unsigned char *sp, int base, mp_ptr up, mp_size_t un)
{
  unsigned bits;

  assert (un > 0);
  assert (up[un-1] > 0);

  bits = mpn_base_power_of_two_p (base);
  if (bits)
    return mpn_get_str_bits (sp, bits, up, un);
  else
    {
      struct mpn_base_info info;

      mpn_get_base_info (&info, base);
      return mpn_get_str_other (sp, base, &info, up, un);
    }
}

static mp_size_t
mpn_set_str_bits (mp_ptr rp, const unsigned char *sp, size_t sn,
		  unsigned bits)
{
  mp_size_t rn;
  size_t j;
  unsigned shift;

  for (j = sn, rn = 0, shift = 0; j-- > 0; )
    {
      if (shift == 0)
	{
	  rp[rn++] = sp[j];
	  shift += bits;
	}
      else
	{
	  rp[rn-1] |= (mp_limb_t) sp[j] << shift;
	  shift += bits;
	  if (shift >= GMP_LIMB_BITS)
	    {
	      shift -= GMP_LIMB_BITS;
	      if (shift > 0)
		rp[rn++] = (mp_limb_t) sp[j] >> (bits - shift);
	    }
	}
    }
  rn = mpn_normalized_size (rp, rn);
  return rn;
}

static mp_size_t
mpn_set_str_other (mp_ptr rp, const unsigned char *sp, size_t sn,
		   mp_limb_t b, const struct mpn_base_info *info)
{
  mp_size_t rn;
  mp_limb_t w;
  unsigned k;
  size_t j;

  k = 1 + (sn - 1) % info->exp;

  j = 0;
  w = sp[j++];
  for (; --k > 0; )
    w = w * b + sp[j++];

  rp[0] = w;

  for (rn = (w > 0); j < sn;)
    {
      mp_limb_t cy;

      w = sp[j++];
      for (k = 1; k < info->exp; k++)
	w = w * b + sp[j++];

      cy = mpn_mul_1 (rp, rp, rn, info->bb);
      cy += mpn_add_1 (rp, rp, rn, w);
      if (cy > 0)
	rp[rn++] = cy;
    }
  assert (j == sn);

  return rn;
}

mp_size_t
mpn_set_str (mp_ptr rp, const unsigned char *sp, size_t sn, int base)
{
  unsigned bits;

  if (sn == 0)
    return 0;

  bits = mpn_base_power_of_two_p (base);
  if (bits)
    return mpn_set_str_bits (rp, sp, sn, bits);
  else
    {
      struct mpn_base_info info;

      mpn_get_base_info (&info, base);
      return mpn_set_str_other (rp, sp, sn, base, &info);
    }
}


/* MPZ interface */
void
mpz_init (mpz_t r)
{
  r->_mp_alloc = 1;
  r->_mp_size = 0;
  r->_mp_d = gmp_xalloc_limbs (1);
}

/* The utility of this function is a bit limited, since many functions
   assigns the result variable using mpz_swap. */
void
mpz_init2 (mpz_t r, mp_bitcnt_t bits)
{
  mp_size_t rn;

  bits -= (bits != 0);		/* Round down, except if 0 */
  rn = 1 + bits / GMP_LIMB_BITS;

  r->_mp_alloc = rn;
  r->_mp_size = 0;
  r->_mp_d = gmp_xalloc_limbs (rn);
}

void
mpz_clear (mpz_t r)
{
  gmp_free (r->_mp_d);
}

void *
mpz_realloc (mpz_t r, mp_size_t size)
{
  size = GMP_MAX (size, 1);

  r->_mp_d = gmp_xrealloc_limbs (r->_mp_d, size);
  r->_mp_alloc = size;

  if (GMP_ABS (r->_mp_size) > size)
    r->_mp_size = 0;

  return r->_mp_d;
}

/* Realloc for an mpz_t WHAT if it has less than NEEDED limbs.  */
#define MPZ_REALLOC(z,n) ((n) > (z)->_mp_alloc			\
			  ? mpz_realloc(z,n)			\
			  : (z)->_mp_d)

/* MPZ assignment and basic conversions. */
void
mpz_set_si (mpz_t r, signed long int x)
{
  if (x >= 0)
    mpz_set_ui (r, x);
  else /* (x < 0) */
    {
      r->_mp_size = -1;
      r->_mp_d[0] = GMP_NEG_CAST (unsigned long int, x);
    }
}

void
mpz_set_ui (mpz_t r, unsigned long int x)
{
  if (x > 0)
    {
      r->_mp_size = 1;
      r->_mp_d[0] = x;
    }
  else
    r->_mp_size = 0;
}

void
mpz_set (mpz_t r, const mpz_t x)
{
  /* Allow the NOP r == x */
  if (r != x)
    {
      mp_size_t n;
      mp_ptr rp;

      n = GMP_ABS (x->_mp_size);
      rp = MPZ_REALLOC (r, n);

      mpn_copyi (rp, x->_mp_d, n);
      r->_mp_size = x->_mp_size;
    }
}

void
mpz_init_set_si (mpz_t r, signed long int x)
{
  mpz_init (r);
  mpz_set_si (r, x);
}

void
mpz_init_set_ui (mpz_t r, unsigned long int x)
{
  mpz_init (r);
  mpz_set_ui (r, x);
}

void
mpz_init_set (mpz_t r, const mpz_t x)
{
  mpz_init (r);
  mpz_set (r, x);
}

int
mpz_fits_slong_p (const mpz_t u)
{
  mp_size_t us = u->_mp_size;

  if (us == 0)
    return 1;
  else if (us == 1)
    return u->_mp_d[0] < GMP_LIMB_HIGHBIT;
  else if (us == -1)
    return u->_mp_d[0] <= GMP_LIMB_HIGHBIT;
  else
    return 0;
}

int
mpz_fits_ulong_p (const mpz_t u)
{
  mp_size_t us = u->_mp_size;

  return (us == (us > 0));
}

long int
mpz_get_si (const mpz_t u)
{
  mp_size_t us = u->_mp_size;

  if (us > 0)
    return (long) (u->_mp_d[0] & ~GMP_LIMB_HIGHBIT);
  else if (us < 0)
    return (long) (- u->_mp_d[0] | GMP_LIMB_HIGHBIT);
  else
    return 0;
}

unsigned long int
mpz_get_ui (const mpz_t u)
{
  return u->_mp_size == 0 ? 0 : u->_mp_d[0];
}

size_t
mpz_size (const mpz_t u)
{
  return GMP_ABS (u->_mp_size);
}

mp_limb_t
mpz_getlimbn (const mpz_t u, mp_size_t n)
{
  if (n >= 0 && n < GMP_ABS (u->_mp_size))
    return u->_mp_d[n];
  else
    return 0;
}

void
mpz_realloc2 (mpz_t x, mp_bitcnt_t n)
{
  mpz_realloc (x, 1 + (n - (n != 0)) / GMP_LIMB_BITS);
}

mp_srcptr
mpz_limbs_read (mpz_srcptr x)
{
  return x->_mp_d;;
}

mp_ptr
mpz_limbs_modify (mpz_t x, mp_size_t n)
{
  assert (n > 0);
  return MPZ_REALLOC (x, n);
}

mp_ptr
mpz_limbs_write (mpz_t x, mp_size_t n)
{
  return mpz_limbs_modify (x, n);
}

void
mpz_limbs_finish (mpz_t x, mp_size_t xs)
{
  mp_size_t xn;
  xn = mpn_normalized_size (x->_mp_d, GMP_ABS (xs));
  x->_mp_size = xs < 0 ? -xn : xn;
}

mpz_srcptr
mpz_roinit_n (mpz_t x, mp_srcptr xp, mp_size_t xs)
{
  x->_mp_alloc = 0;
  x->_mp_d = (mp_ptr) xp;
  mpz_limbs_finish (x, xs);
  return x;
}


/* Conversions and comparison to double. */
void
mpz_set_d (mpz_t r, double x)
{
  int sign;
  mp_ptr rp;
  mp_size_t rn, i;
  double B;
  double Bi;
  mp_limb_t f;

  /* x != x is true when x is a NaN, and x == x * 0.5 is true when x is
     zero or infinity. */
  if (x != x || x == x * 0.5)
    {
      r->_mp_size = 0;
      return;
    }

  sign = x < 0.0 ;
  if (sign)
    x = - x;

  if (x < 1.0)
    {
      r->_mp_size = 0;
      return;
    }
  B = 2.0 * (double) GMP_LIMB_HIGHBIT;
  Bi = 1.0 / B;
  for (rn = 1; x >= B; rn++)
    x *= Bi;

  rp = MPZ_REALLOC (r, rn);

  f = (mp_limb_t) x;
  x -= f;
  assert (x < 1.0);
  i = rn-1;
  rp[i] = f;
  while (--i >= 0)
    {
      x = B * x;
      f = (mp_limb_t) x;
      x -= f;
      assert (x < 1.0);
      rp[i] = f;
    }

  r->_mp_size = sign ? - rn : rn;
}

void
mpz_init_set_d (mpz_t r, double x)
{
  mpz_init (r);
  mpz_set_d (r, x);
}

double
mpz_get_d (const mpz_t u)
{
  mp_size_t un;
  double x;
  double B = 2.0 * (double) GMP_LIMB_HIGHBIT;

  un = GMP_ABS (u->_mp_size);

  if (un == 0)
    return 0.0;

  x = u->_mp_d[--un];
  while (un > 0)
    x = B*x + u->_mp_d[--un];

  if (u->_mp_size < 0)
    x = -x;

  return x;
}

int
mpz_cmpabs_d (const mpz_t x, double d)
{
  mp_size_t xn;
  double B, Bi;
  mp_size_t i;

  xn = x->_mp_size;
  d = GMP_ABS (d);

  if (xn != 0)
    {
      xn = GMP_ABS (xn);

      B = 2.0 * (double) GMP_LIMB_HIGHBIT;
      Bi = 1.0 / B;

      /* Scale d so it can be compared with the top limb. */
      for (i = 1; i < xn; i++)
	d *= Bi;

      if (d >= B)
	return -1;

      /* Compare floor(d) to top limb, subtract and cancel when equal. */
      for (i = xn; i-- > 0;)
	{
	  mp_limb_t f, xl;

	  f = (mp_limb_t) d;
	  xl = x->_mp_d[i];
	  if (xl > f)
	    return 1;
	  else if (xl < f)
	    return -1;
	  d = B * (d - f);
	}
    }
  return - (d > 0.0);
}

int
mpz_cmp_d (const mpz_t x, double d)
{
  if (x->_mp_size < 0)
    {
      if (d >= 0.0)
	return -1;
      else
	return -mpz_cmpabs_d (x, d);
    }
  else
    {
      if (d < 0.0)
	return 1;
      else
	return mpz_cmpabs_d (x, d);
    }
}


/* MPZ comparisons and the like. */
int
mpz_sgn (const mpz_t u)
{
  mp_size_t usize = u->_mp_size;

  return (usize > 0) - (usize < 0);
}

int
mpz_cmp_si (const mpz_t u, long v)
{
  mp_size_t usize = u->_mp_size;

  if (usize < -1)
    return -1;
  else if (v >= 0)
    return mpz_cmp_ui (u, v);
  else if (usize >= 0)
    return 1;
  else /* usize == -1 */
    {
      mp_limb_t ul = u->_mp_d[0];
      if ((mp_limb_t)GMP_NEG_CAST (unsigned long int, v) < ul)
	return -1;
      else
	return (mp_limb_t)GMP_NEG_CAST (unsigned long int, v) > ul;
    }
}

int
mpz_cmp_ui (const mpz_t u, unsigned long v)
{
  mp_size_t usize = u->_mp_size;

  if (usize > 1)
    return 1;
  else if (usize < 0)
    return -1;
  else
    {
      mp_limb_t ul = (usize > 0) ? u->_mp_d[0] : 0;
      return (ul > v) - (ul < v);
    }
}

int
mpz_cmp (const mpz_t a, const mpz_t b)
{
  mp_size_t asize = a->_mp_size;
  mp_size_t bsize = b->_mp_size;

  if (asize != bsize)
    return (asize < bsize) ? -1 : 1;
  else if (asize >= 0)
    return mpn_cmp (a->_mp_d, b->_mp_d, asize);
  else
    return mpn_cmp (b->_mp_d, a->_mp_d, -asize);
}

int
mpz_cmpabs_ui (const mpz_t u, unsigned long v)
{
  mp_size_t un = GMP_ABS (u->_mp_size);
  mp_limb_t ul;

  if (un > 1)
    return 1;

  ul = (un == 1) ? u->_mp_d[0] : 0;

  return (ul > v) - (ul < v);
}

int
mpz_cmpabs (const mpz_t u, const mpz_t v)
{
  return mpn_cmp4 (u->_mp_d, GMP_ABS (u->_mp_size),
		   v->_mp_d, GMP_ABS (v->_mp_size));
}

void
mpz_abs (mpz_t r, const mpz_t u)
{
  if (r != u)
    mpz_set (r, u);

  r->_mp_size = GMP_ABS (r->_mp_size);
}

void
mpz_neg (mpz_t r, const mpz_t u)
{
  if (r != u)
    mpz_set (r, u);

  r->_mp_size = -r->_mp_size;
}

void
mpz_swap (mpz_t u, mpz_t v)
{
  MP_SIZE_T_SWAP (u->_mp_size, v->_mp_size);
  MP_SIZE_T_SWAP (u->_mp_alloc, v->_mp_alloc);
  MP_PTR_SWAP (u->_mp_d, v->_mp_d);
}


/* MPZ addition and subtraction */

/* Adds to the absolute value. Returns new size, but doesn't store it. */
static mp_size_t
mpz_abs_add_ui (mpz_t r, const mpz_t a, unsigned long b)
{
  mp_size_t an;
  mp_ptr rp;
  mp_limb_t cy;

  an = GMP_ABS (a->_mp_size);
  if (an == 0)
    {
      r->_mp_d[0] = b;
      return b > 0;
    }

  rp = MPZ_REALLOC (r, an + 1);

  cy = mpn_add_1 (rp, a->_mp_d, an, b);
  rp[an] = cy;
  an += cy;

  return an;
}

/* Subtract from the absolute value. Returns new size, (or -1 on underflow),
   but doesn't store it. */
static mp_size_t
mpz_abs_sub_ui (mpz_t r, const mpz_t a, unsigned long b)
{
  mp_size_t an = GMP_ABS (a->_mp_size);
  mp_ptr rp = MPZ_REALLOC (r, an);

  if (an == 0)
    {
      rp[0] = b;
      return -(b > 0);
    }
  else if (an == 1 && a->_mp_d[0] < b)
    {
      rp[0] = b - a->_mp_d[0];
      return -1;
    }
  else
    {
      gmp_assert_nocarry (mpn_sub_1 (rp, a->_mp_d, an, b));
      return mpn_normalized_size (rp, an);
    }
}

void
mpz_add_ui (mpz_t r, const mpz_t a, unsigned long b)
{
  if (a->_mp_size >= 0)
    r->_mp_size = mpz_abs_add_ui (r, a, b);
  else
    r->_mp_size = -mpz_abs_sub_ui (r, a, b);
}

void
mpz_sub_ui (mpz_t r, const mpz_t a, unsigned long b)
{
  if (a->_mp_size < 0)
    r->_mp_size = -mpz_abs_add_ui (r, a, b);
  else
    r->_mp_size = mpz_abs_sub_ui (r, a, b);
}

void
mpz_ui_sub (mpz_t r, unsigned long a, const mpz_t b)
{
  if (b->_mp_size < 0)
    r->_mp_size = mpz_abs_add_ui (r, b, a);
  else
    r->_mp_size = -mpz_abs_sub_ui (r, b, a);
}

static mp_size_t
mpz_abs_add (mpz_t r, const mpz_t a, const mpz_t b)
{
  mp_size_t an = GMP_ABS (a->_mp_size);
  mp_size_t bn = GMP_ABS (b->_mp_size);
  mp_ptr rp;
  mp_limb_t cy;

  if (an < bn)
    {
      MPZ_SRCPTR_SWAP (a, b);
      MP_SIZE_T_SWAP (an, bn);
    }

  rp = MPZ_REALLOC (r, an + 1);
  cy = mpn_add (rp, a->_mp_d, an, b->_mp_d, bn);

  rp[an] = cy;

  return an + cy;
}

static mp_size_t
mpz_abs_sub (mpz_t r, const mpz_t a, const mpz_t b)
{
  mp_size_t an = GMP_ABS (a->_mp_size);
  mp_size_t bn = GMP_ABS (b->_mp_size);
  int cmp;
  mp_ptr rp;

  cmp = mpn_cmp4 (a->_mp_d, an, b->_mp_d, bn);
  if (cmp > 0)
    {
      rp = MPZ_REALLOC (r, an);
      gmp_assert_nocarry (mpn_sub (rp, a->_mp_d, an, b->_mp_d, bn));
      return mpn_normalized_size (rp, an);
    }
  else if (cmp < 0)
    {
      rp = MPZ_REALLOC (r, bn);
      gmp_assert_nocarry (mpn_sub (rp, b->_mp_d, bn, a->_mp_d, an));
      return -mpn_normalized_size (rp, bn);
    }
  else
    return 0;
}

void
mpz_add (mpz_t r, const mpz_t a, const mpz_t b)
{
  mp_size_t rn;

  if ( (a->_mp_size ^ b->_mp_size) >= 0)
    rn = mpz_abs_add (r, a, b);
  else
    rn = mpz_abs_sub (r, a, b);

  r->_mp_size = a->_mp_size >= 0 ? rn : - rn;
}

void
mpz_sub (mpz_t r, const mpz_t a, const mpz_t b)
{
  mp_size_t rn;

  if ( (a->_mp_size ^ b->_mp_size) >= 0)
    rn = mpz_abs_sub (r, a, b);
  else
    rn = mpz_abs_add (r, a, b);

  r->_mp_size = a->_mp_size >= 0 ? rn : - rn;
}


/* MPZ multiplication */
void
mpz_mul_si (mpz_t r, const mpz_t u, long int v)
{
  if (v < 0)
    {
      mpz_mul_ui (r, u, GMP_NEG_CAST (unsigned long int, v));
      mpz_neg (r, r);
    }
  else
    mpz_mul_ui (r, u, (unsigned long int) v);
}

void
mpz_mul_ui (mpz_t r, const mpz_t u, unsigned long int v)
{
  mp_size_t un, us;
  mp_ptr tp;
  mp_limb_t cy;

  us = u->_mp_size;

  if (us == 0 || v == 0)
    {
      r->_mp_size = 0;
      return;
    }

  un = GMP_ABS (us);

  tp = MPZ_REALLOC (r, un + 1);
  cy = mpn_mul_1 (tp, u->_mp_d, un, v);
  tp[un] = cy;

  un += (cy > 0);
  r->_mp_size = (us < 0) ? - un : un;
}

void
mpz_mul (mpz_t r, const mpz_t u, const mpz_t v)
{
  int sign;
  mp_size_t un, vn, rn;
  mpz_t t;
  mp_ptr tp;

  un = u->_mp_size;
  vn = v->_mp_size;

  if (un == 0 || vn == 0)
    {
      r->_mp_size = 0;
      return;
    }

  sign = (un ^ vn) < 0;

  un = GMP_ABS (un);
  vn = GMP_ABS (vn);

  mpz_init2 (t, (un + vn) * GMP_LIMB_BITS);

  tp = t->_mp_d;
  if (un >= vn)
    mpn_mul (tp, u->_mp_d, un, v->_mp_d, vn);
  else
    mpn_mul (tp, v->_mp_d, vn, u->_mp_d, un);

  rn = un + vn;
  rn -= tp[rn-1] == 0;

  t->_mp_size = sign ? - rn : rn;
  mpz_swap (r, t);
  mpz_clear (t);
}

void
mpz_mul_2exp (mpz_t r, const mpz_t u, mp_bitcnt_t bits)
{
  mp_size_t un, rn;
  mp_size_t limbs;
  unsigned shift;
  mp_ptr rp;

  un = GMP_ABS (u->_mp_size);
  if (un == 0)
    {
      r->_mp_size = 0;
      return;
    }

  limbs = bits / GMP_LIMB_BITS;
  shift = bits % GMP_LIMB_BITS;

  rn = un + limbs + (shift > 0);
  rp = MPZ_REALLOC (r, rn);
  if (shift > 0)
    {
      mp_limb_t cy = mpn_lshift (rp + limbs, u->_mp_d, un, shift);
      rp[rn-1] = cy;
      rn -= (cy == 0);
    }
  else
    mpn_copyd (rp + limbs, u->_mp_d, un);

  while (limbs > 0)
    rp[--limbs] = 0;

  r->_mp_size = (u->_mp_size < 0) ? - rn : rn;
}

void
mpz_addmul_ui (mpz_t r, const mpz_t u, unsigned long int v)
{
  mpz_t t;
  mpz_init (t);
  mpz_mul_ui (t, u, v);
  mpz_add (r, r, t);
  mpz_clear (t);
}

void
mpz_submul_ui (mpz_t r, const mpz_t u, unsigned long int v)
{
  mpz_t t;
  mpz_init (t);
  mpz_mul_ui (t, u, v);
  mpz_sub (r, r, t);
  mpz_clear (t);
}

void
mpz_addmul (mpz_t r, const mpz_t u, const mpz_t v)
{
  mpz_t t;
  mpz_init (t);
  mpz_mul (t, u, v);
  mpz_add (r, r, t);
  mpz_clear (t);
}

void
mpz_submul (mpz_t r, const mpz_t u, const mpz_t v)
{
  mpz_t t;
  mpz_init (t);
  mpz_mul (t, u, v);
  mpz_sub (r, r, t);
  mpz_clear (t);
}


/* MPZ division */
enum mpz_div_round_mode { GMP_DIV_FLOOR, GMP_DIV_CEIL, GMP_DIV_TRUNC };

/* Allows q or r to be zero. Returns 1 iff remainder is non-zero. */
static int
mpz_div_qr (mpz_t q, mpz_t r,
	    const mpz_t n, const mpz_t d, enum mpz_div_round_mode mode)
{
  mp_size_t ns, ds, nn, dn, qs;
  ns = n->_mp_size;
  ds = d->_mp_size;

  if (ds == 0)
    gmp_die("mpz_div_qr: Divide by zero.");

  if (ns == 0)
    {
      if (q)
	q->_mp_size = 0;
      if (r)
	r->_mp_size = 0;
      return 0;
    }

  nn = GMP_ABS (ns);
  dn = GMP_ABS (ds);

  qs = ds ^ ns;

  if (nn < dn)
    {
      if (mode == GMP_DIV_CEIL && qs >= 0)
	{
	  /* q = 1, r = n - d */
	  if (r)
	    mpz_sub (r, n, d);
	  if (q)
	    mpz_set_ui (q, 1);
	}
      else if (mode == GMP_DIV_FLOOR && qs < 0)
	{
	  /* q = -1, r = n + d */
	  if (r)
	    mpz_add (r, n, d);
	  if (q)
	    mpz_set_si (q, -1);
	}
      else
	{
	  /* q = 0, r = d */
	  if (r)
	    mpz_set (r, n);
	  if (q)
	    q->_mp_size = 0;
	}
      return 1;
    }
  else
    {
      mp_ptr np, qp;
      mp_size_t qn, rn;
      mpz_t tq, tr;

      mpz_init_set (tr, n);
      np = tr->_mp_d;

      qn = nn - dn + 1;

      if (q)
	{
	  mpz_init2 (tq, qn * GMP_LIMB_BITS);
	  qp = tq->_mp_d;
	}
      else
	qp = NULL;

      mpn_div_qr (qp, np, nn, d->_mp_d, dn);

      if (qp)
	{
	  qn -= (qp[qn-1] == 0);

	  tq->_mp_size = qs < 0 ? -qn : qn;
	}
      rn = mpn_normalized_size (np, dn);
      tr->_mp_size = ns < 0 ? - rn : rn;

      if (mode == GMP_DIV_FLOOR && qs < 0 && rn != 0)
	{
	  if (q)
	    mpz_sub_ui (tq, tq, 1);
	  if (r)
	    mpz_add (tr, tr, d);
	}
      else if (mode == GMP_DIV_CEIL && qs >= 0 && rn != 0)
	{
	  if (q)
	    mpz_add_ui (tq, tq, 1);
	  if (r)
	    mpz_sub (tr, tr, d);
	}

      if (q)
	{
	  mpz_swap (tq, q);
	  mpz_clear (tq);
	}
      if (r)
	mpz_swap (tr, r);

      mpz_clear (tr);

      return rn != 0;
    }
}

void
mpz_cdiv_qr (mpz_t q, mpz_t r, const mpz_t n, const mpz_t d)
{
  mpz_div_qr (q, r, n, d, GMP_DIV_CEIL);
}

void
mpz_fdiv_qr (mpz_t q, mpz_t r, const mpz_t n, const mpz_t d)
{
  mpz_div_qr (q, r, n, d, GMP_DIV_FLOOR);
}

void
mpz_tdiv_qr (mpz_t q, mpz_t r, const mpz_t n, const mpz_t d)
{
  mpz_div_qr (q, r, n, d, GMP_DIV_TRUNC);
}

void
mpz_cdiv_q (mpz_t q, const mpz_t n, const mpz_t d)
{
  mpz_div_qr (q, NULL, n, d, GMP_DIV_CEIL);
}

void
mpz_fdiv_q (mpz_t q, const mpz_t n, const mpz_t d)
{
  mpz_div_qr (q, NULL, n, d, GMP_DIV_FLOOR);
}

void
mpz_tdiv_q (mpz_t q, const mpz_t n, const mpz_t d)
{
  mpz_div_qr (q, NULL, n, d, GMP_DIV_TRUNC);
}

void
mpz_cdiv_r (mpz_t r, const mpz_t n, const mpz_t d)
{
  mpz_div_qr (NULL, r, n, d, GMP_DIV_CEIL);
}

void
mpz_fdiv_r (mpz_t r, const mpz_t n, const mpz_t d)
{
  mpz_div_qr (NULL, r, n, d, GMP_DIV_FLOOR);
}

void
mpz_tdiv_r (mpz_t r, const mpz_t n, const mpz_t d)
{
  mpz_div_qr (NULL, r, n, d, GMP_DIV_TRUNC);
}

void
mpz_mod (mpz_t r, const mpz_t n, const mpz_t d)
{
  mpz_div_qr (NULL, r, n, d, d->_mp_size >= 0 ? GMP_DIV_FLOOR : GMP_DIV_CEIL);
}

static void
mpz_div_q_2exp (mpz_t q, const mpz_t u, mp_bitcnt_t bit_index,
		enum mpz_div_round_mode mode)
{
  mp_size_t un, qn;
  mp_size_t limb_cnt;
  mp_ptr qp;
  int adjust;

  un = u->_mp_size;
  if (un == 0)
    {
      q->_mp_size = 0;
      return;
    }
  limb_cnt = bit_index / GMP_LIMB_BITS;
  qn = GMP_ABS (un) - limb_cnt;
  bit_index %= GMP_LIMB_BITS;

  if (mode == ((un > 0) ? GMP_DIV_CEIL : GMP_DIV_FLOOR)) /* un != 0 here. */
    /* Note: Below, the final indexing at limb_cnt is valid because at
       that point we have qn > 0. */
    adjust = (qn <= 0
	      || !mpn_zero_p (u->_mp_d, limb_cnt)
	      || (u->_mp_d[limb_cnt]
		  & (((mp_limb_t) 1 << bit_index) - 1)));
  else
    adjust = 0;

  if (qn <= 0)
    qn = 0;

  else
    {
      qp = MPZ_REALLOC (q, qn);

      if (bit_index != 0)
	{
	  mpn_rshift (qp, u->_mp_d + limb_cnt, qn, bit_index);
	  qn -= qp[qn - 1] == 0;
	}
      else
	{
	  mpn_copyi (qp, u->_mp_d + limb_cnt, qn);
	}
    }

  q->_mp_size = qn;

  if (adjust)
    mpz_add_ui (q, q, 1);
  if (un < 0)
    mpz_neg (q, q);
}

static void
mpz_div_r_2exp (mpz_t r, const mpz_t u, mp_bitcnt_t bit_index,
		enum mpz_div_round_mode mode)
{
  mp_size_t us, un, rn;
  mp_ptr rp;
  mp_limb_t mask;

  us = u->_mp_size;
  if (us == 0 || bit_index == 0)
    {
      r->_mp_size = 0;
      return;
    }
  rn = (bit_index + GMP_LIMB_BITS - 1) / GMP_LIMB_BITS;
  assert (rn > 0);

  rp = MPZ_REALLOC (r, rn);
  un = GMP_ABS (us);

  mask = GMP_LIMB_MAX >> (rn * GMP_LIMB_BITS - bit_index);

  if (rn > un)
    {
      /* Quotient (with truncation) is zero, and remainder is
	 non-zero */
      if (mode == ((us > 0) ? GMP_DIV_CEIL : GMP_DIV_FLOOR)) /* us != 0 here. */
	{
	  /* Have to negate and sign extend. */
	  mp_size_t i;
	  mp_limb_t cy;

	  for (cy = 1, i = 0; i < un; i++)
	    {
	      mp_limb_t s = ~u->_mp_d[i] + cy;
	      cy = s < cy;
	      rp[i] = s;
	    }
	  assert (cy == 0);
	  for (; i < rn - 1; i++)
	    rp[i] = GMP_LIMB_MAX;

	  rp[rn-1] = mask;
	  us = -us;
	}
      else
	{
	  /* Just copy */
	  if (r != u)
	    mpn_copyi (rp, u->_mp_d, un);

	  rn = un;
	}
    }
  else
    {
      if (r != u)
	mpn_copyi (rp, u->_mp_d, rn - 1);

      rp[rn-1] = u->_mp_d[rn-1] & mask;

      if (mode == ((us > 0) ? GMP_DIV_CEIL : GMP_DIV_FLOOR)) /* us != 0 here. */
	{
	  /* If r != 0, compute 2^{bit_count} - r. */
	  mp_size_t i;

	  for (i = 0; i < rn && rp[i] == 0; i++)
	    ;
	  if (i < rn)
	    {
	      /* r > 0, need to flip sign. */
	      rp[i] = ~rp[i] + 1;
	      while (++i < rn)
		rp[i] = ~rp[i];

	      rp[rn-1] &= mask;

	      /* us is not used for anything else, so we can modify it
		 here to indicate flipped sign. */
	      us = -us;
	    }
	}
    }
  rn = mpn_normalized_size (rp, rn);
  r->_mp_size = us < 0 ? -rn : rn;
}

void
mpz_cdiv_q_2exp (mpz_t r, const mpz_t u, mp_bitcnt_t cnt)
{
  mpz_div_q_2exp (r, u, cnt, GMP_DIV_CEIL);
}

void
mpz_fdiv_q_2exp (mpz_t r, const mpz_t u, mp_bitcnt_t cnt)
{
  mpz_div_q_2exp (r, u, cnt, GMP_DIV_FLOOR);
}

void
mpz_tdiv_q_2exp (mpz_t r, const mpz_t u, mp_bitcnt_t cnt)
{
  mpz_div_q_2exp (r, u, cnt, GMP_DIV_TRUNC);
}

void
mpz_cdiv_r_2exp (mpz_t r, const mpz_t u, mp_bitcnt_t cnt)
{
  mpz_div_r_2exp (r, u, cnt, GMP_DIV_CEIL);
}

void
mpz_fdiv_r_2exp (mpz_t r, const mpz_t u, mp_bitcnt_t cnt)
{
  mpz_div_r_2exp (r, u, cnt, GMP_DIV_FLOOR);
}

void
mpz_tdiv_r_2exp (mpz_t r, const mpz_t u, mp_bitcnt_t cnt)
{
  mpz_div_r_2exp (r, u, cnt, GMP_DIV_TRUNC);
}

void
mpz_divexact (mpz_t q, const mpz_t n, const mpz_t d)
{
  gmp_assert_nocarry (mpz_div_qr (q, NULL, n, d, GMP_DIV_TRUNC));
}

int
mpz_divisible_p (const mpz_t n, const mpz_t d)
{
  return mpz_div_qr (NULL, NULL, n, d, GMP_DIV_TRUNC) == 0;
}

int
mpz_congruent_p (const mpz_t a, const mpz_t b, const mpz_t m)
{
  mpz_t t;
  int res;

  /* a == b (mod 0) iff a == b */
  if (mpz_sgn (m) == 0)
    return (mpz_cmp (a, b) == 0);

  mpz_init (t);
  mpz_sub (t, a, b);
  res = mpz_divisible_p (t, m);
  mpz_clear (t);

  return res;
}

static unsigned long
mpz_div_qr_ui (mpz_t q, mpz_t r,
	       const mpz_t n, unsigned long d, enum mpz_div_round_mode mode)
{
  mp_size_t ns, qn;
  mp_ptr qp;
  mp_limb_t rl;
  mp_size_t rs;

  ns = n->_mp_size;
  if (ns == 0)
    {
      if (q)
	q->_mp_size = 0;
      if (r)
	r->_mp_size = 0;
      return 0;
    }

  qn = GMP_ABS (ns);
  if (q)
    qp = MPZ_REALLOC (q, qn);
  else
    qp = NULL;

  rl = mpn_div_qr_1 (qp, n->_mp_d, qn, d);
  assert (rl < d);

  rs = rl > 0;
  rs = (ns < 0) ? -rs : rs;

  if (rl > 0 && ( (mode == GMP_DIV_FLOOR && ns < 0)
		  || (mode == GMP_DIV_CEIL && ns >= 0)))
    {
      if (q)
	gmp_assert_nocarry (mpn_add_1 (qp, qp, qn, 1));
      rl = d - rl;
      rs = -rs;
    }

  if (r)
    {
      r->_mp_d[0] = rl;
      r->_mp_size = rs;
    }
  if (q)
    {
      qn -= (qp[qn-1] == 0);
      assert (qn == 0 || qp[qn-1] > 0);

      q->_mp_size = (ns < 0) ? - qn : qn;
    }

  return rl;
}

unsigned long
mpz_cdiv_qr_ui (mpz_t q, mpz_t r, const mpz_t n, unsigned long d)
{
  return mpz_div_qr_ui (q, r, n, d, GMP_DIV_CEIL);
}

unsigned long
mpz_fdiv_qr_ui (mpz_t q, mpz_t r, const mpz_t n, unsigned long d)
{
  return mpz_div_qr_ui (q, r, n, d, GMP_DIV_FLOOR);
}

unsigned long
mpz_tdiv_qr_ui (mpz_t q, mpz_t r, const mpz_t n, unsigned long d)
{
  return mpz_div_qr_ui (q, r, n, d, GMP_DIV_TRUNC);
}

unsigned long
mpz_cdiv_q_ui (mpz_t q, const mpz_t n, unsigned long d)
{
  return mpz_div_qr_ui (q, NULL, n, d, GMP_DIV_CEIL);
}

unsigned long
mpz_fdiv_q_ui (mpz_t q, const mpz_t n, unsigned long d)
{
  return mpz_div_qr_ui (q, NULL, n, d, GMP_DIV_FLOOR);
}

unsigned long
mpz_tdiv_q_ui (mpz_t q, const mpz_t n, unsigned long d)
{
  return mpz_div_qr_ui (q, NULL, n, d, GMP_DIV_TRUNC);
}

unsigned long
mpz_cdiv_r_ui (mpz_t r, const mpz_t n, unsigned long d)
{
  return mpz_div_qr_ui (NULL, r, n, d, GMP_DIV_CEIL);
}
unsigned long
mpz_fdiv_r_ui (mpz_t r, const mpz_t n, unsigned long d)
{
  return mpz_div_qr_ui (NULL, r, n, d, GMP_DIV_FLOOR);
}
unsigned long
mpz_tdiv_r_ui (mpz_t r, const mpz_t n, unsigned long d)
{
  return mpz_div_qr_ui (NULL, r, n, d, GMP_DIV_TRUNC);
}

unsigned long
mpz_cdiv_ui (const mpz_t n, unsigned long d)
{
  return mpz_div_qr_ui (NULL, NULL, n, d, GMP_DIV_CEIL);
}

unsigned long
mpz_fdiv_ui (const mpz_t n, unsigned long d)
{
  return mpz_div_qr_ui (NULL, NULL, n, d, GMP_DIV_FLOOR);
}

unsigned long
mpz_tdiv_ui (const mpz_t n, unsigned long d)
{
  return mpz_div_qr_ui (NULL, NULL, n, d, GMP_DIV_TRUNC);
}

unsigned long
mpz_mod_ui (mpz_t r, const mpz_t n, unsigned long d)
{
  return mpz_div_qr_ui (NULL, r, n, d, GMP_DIV_FLOOR);
}

void
mpz_divexact_ui (mpz_t q, const mpz_t n, unsigned long d)
{
  gmp_assert_nocarry (mpz_div_qr_ui (q, NULL, n, d, GMP_DIV_TRUNC));
}

int
mpz_divisible_ui_p (const mpz_t n, unsigned long d)
{
  return mpz_div_qr_ui (NULL, NULL, n, d, GMP_DIV_TRUNC) == 0;
}


/* GCD */
static mp_limb_t
mpn_gcd_11 (mp_limb_t u, mp_limb_t v)
{
  unsigned shift;

  assert ( (u | v) > 0);

  if (u == 0)
    return v;
  else if (v == 0)
    return u;

  gmp_ctz (shift, u | v);

  u >>= shift;
  v >>= shift;

  if ( (u & 1) == 0)
    MP_LIMB_T_SWAP (u, v);

  while ( (v & 1) == 0)
    v >>= 1;

  while (u != v)
    {
      if (u > v)
	{
	  u -= v;
	  do
	    u >>= 1;
	  while ( (u & 1) == 0);
	}
      else
	{
	  v -= u;
	  do
	    v >>= 1;
	  while ( (v & 1) == 0);
	}
    }
  return u << shift;
}

unsigned long
mpz_gcd_ui (mpz_t g, const mpz_t u, unsigned long v)
{
  mp_size_t un;

  if (v == 0)
    {
      if (g)
	mpz_abs (g, u);
    }
  else
    {
      un = GMP_ABS (u->_mp_size);
      if (un != 0)
	v = mpn_gcd_11 (mpn_div_qr_1 (NULL, u->_mp_d, un, v), v);

      if (g)
	mpz_set_ui (g, v);
    }

  return v;
}

static mp_bitcnt_t
mpz_make_odd (mpz_t r)
{
  mp_bitcnt_t shift;

  assert (r->_mp_size > 0);
  /* Count trailing zeros, equivalent to mpn_scan1, because we know that there is a 1 */
  shift = mpn_common_scan (r->_mp_d[0], 0, r->_mp_d, 0, 0);
  mpz_tdiv_q_2exp (r, r, shift);

  return shift;
}

void
mpz_gcd (mpz_t g, const mpz_t u, const mpz_t v)
{
  mpz_t tu, tv;
  mp_bitcnt_t uz, vz, gz;

  if (u->_mp_size == 0)
    {
      mpz_abs (g, v);
      return;
    }
  if (v->_mp_size == 0)
    {
      mpz_abs (g, u);
      return;
    }

  mpz_init (tu);
  mpz_init (tv);

  mpz_abs (tu, u);
  uz = mpz_make_odd (tu);
  mpz_abs (tv, v);
  vz = mpz_make_odd (tv);
  gz = GMP_MIN (uz, vz);

  if (tu->_mp_size < tv->_mp_size)
    mpz_swap (tu, tv);

  mpz_tdiv_r (tu, tu, tv);
  if (tu->_mp_size == 0)
    {
      mpz_swap (g, tv);
    }
  else
    for (;;)
      {
	int c;

	mpz_make_odd (tu);
	c = mpz_cmp (tu, tv);
	if (c == 0)
	  {
	    mpz_swap (g, tu);
	    break;
	  }
	if (c < 0)
	  mpz_swap (tu, tv);

	if (tv->_mp_size == 1)
	  {
	    mp_limb_t vl = tv->_mp_d[0];
	    mp_limb_t ul = mpz_tdiv_ui (tu, vl);
	    mpz_set_ui (g, mpn_gcd_11 (ul, vl));
	    break;
	  }
	mpz_sub (tu, tu, tv);
      }
  mpz_clear (tu);
  mpz_clear (tv);
  mpz_mul_2exp (g, g, gz);
}

void
mpz_gcdext (mpz_t g, mpz_t s, mpz_t t, const mpz_t u, const mpz_t v)
{
  mpz_t tu, tv, s0, s1, t0, t1;
  mp_bitcnt_t uz, vz, gz;
  mp_bitcnt_t power;

  if (u->_mp_size == 0)
    {
      /* g = 0 u + sgn(v) v */
      signed long sign = mpz_sgn (v);
      mpz_abs (g, v);
      if (s)
	mpz_set_ui (s, 0);
      if (t)
	mpz_set_si (t, sign);
      return;
    }

  if (v->_mp_size == 0)
    {
      /* g = sgn(u) u + 0 v */
      signed long sign = mpz_sgn (u);
      mpz_abs (g, u);
      if (s)
	mpz_set_si (s, sign);
      if (t)
	mpz_set_ui (t, 0);
      return;
    }

  mpz_init (tu);
  mpz_init (tv);
  mpz_init (s0);
  mpz_init (s1);
  mpz_init (t0);
  mpz_init (t1);

  mpz_abs (tu, u);
  uz = mpz_make_odd (tu);
  mpz_abs (tv, v);
  vz = mpz_make_odd (tv);
  gz = GMP_MIN (uz, vz);

  uz -= gz;
  vz -= gz;

  /* Cofactors corresponding to odd gcd. gz handled later. */
  if (tu->_mp_size < tv->_mp_size)
    {
      mpz_swap (tu, tv);
      MPZ_SRCPTR_SWAP (u, v);
      MPZ_PTR_SWAP (s, t);
      MP_BITCNT_T_SWAP (uz, vz);
    }

  /* Maintain
   *
   * u = t0 tu + t1 tv
   * v = s0 tu + s1 tv
   *
   * where u and v denote the inputs with common factors of two
   * eliminated, and det (s0, t0; s1, t1) = 2^p. Then
   *
   * 2^p tu =  s1 u - t1 v
   * 2^p tv = -s0 u + t0 v
   */

  /* After initial division, tu = q tv + tu', we have
   *
   * u = 2^uz (tu' + q tv)
   * v = 2^vz tv
   *
   * or
   *
   * t0 = 2^uz, t1 = 2^uz q
   * s0 = 0,    s1 = 2^vz
   */

  mpz_setbit (t0, uz);
  mpz_tdiv_qr (t1, tu, tu, tv);
  mpz_mul_2exp (t1, t1, uz);

  mpz_setbit (s1, vz);
  power = uz + vz;

  if (tu->_mp_size > 0)
    {
      mp_bitcnt_t shift;
      shift = mpz_make_odd (tu);
      mpz_mul_2exp (t0, t0, shift);
      mpz_mul_2exp (s0, s0, shift);
      power += shift;

      for (;;)
	{
	  int c;
	  c = mpz_cmp (tu, tv);
	  if (c == 0)
	    break;

	  if (c < 0)
	    {
	      /* tv = tv' + tu
	       *
	       * u = t0 tu + t1 (tv' + tu) = (t0 + t1) tu + t1 tv'
	       * v = s0 tu + s1 (tv' + tu) = (s0 + s1) tu + s1 tv' */

	      mpz_sub (tv, tv, tu);
	      mpz_add (t0, t0, t1);
	      mpz_add (s0, s0, s1);

	      shift = mpz_make_odd (tv);
	      mpz_mul_2exp (t1, t1, shift);
	      mpz_mul_2exp (s1, s1, shift);
	    }
	  else
	    {
	      mpz_sub (tu, tu, tv);
	      mpz_add (t1, t0, t1);
	      mpz_add (s1, s0, s1);

	      shift = mpz_make_odd (tu);
	      mpz_mul_2exp (t0, t0, shift);
	      mpz_mul_2exp (s0, s0, shift);
	    }
	  power += shift;
	}
    }

  /* Now tv = odd part of gcd, and -s0 and t0 are corresponding
     cofactors. */

  mpz_mul_2exp (tv, tv, gz);
  mpz_neg (s0, s0);

  /* 2^p g = s0 u + t0 v. Eliminate one factor of two at a time. To
     adjust cofactors, we need u / g and v / g */

  mpz_divexact (s1, v, tv);
  mpz_abs (s1, s1);
  mpz_divexact (t1, u, tv);
  mpz_abs (t1, t1);

  while (power-- > 0)
    {
      /* s0 u + t0 v = (s0 - v/g) u - (t0 + u/g) v */
      if (mpz_odd_p (s0) || mpz_odd_p (t0))
	{
	  mpz_sub (s0, s0, s1);
	  mpz_add (t0, t0, t1);
	}
      mpz_divexact_ui (s0, s0, 2);
      mpz_divexact_ui (t0, t0, 2);
    }

  /* Arrange so that |s| < |u| / 2g */
  mpz_add (s1, s0, s1);
  if (mpz_cmpabs (s0, s1) > 0)
    {
      mpz_swap (s0, s1);
      mpz_sub (t0, t0, t1);
    }
  if (u->_mp_size < 0)
    mpz_neg (s0, s0);
  if (v->_mp_size < 0)
    mpz_neg (t0, t0);

  mpz_swap (g, tv);
  if (s)
    mpz_swap (s, s0);
  if (t)
    mpz_swap (t, t0);

  mpz_clear (tu);
  mpz_clear (tv);
  mpz_clear (s0);
  mpz_clear (s1);
  mpz_clear (t0);
  mpz_clear (t1);
}

void
mpz_lcm (mpz_t r, const mpz_t u, const mpz_t v)
{
  mpz_t g;

  if (u->_mp_size == 0 || v->_mp_size == 0)
    {
      r->_mp_size = 0;
      return;
    }

  mpz_init (g);

  mpz_gcd (g, u, v);
  mpz_divexact (g, u, g);
  mpz_mul (r, g, v);

  mpz_clear (g);
  mpz_abs (r, r);
}

void
mpz_lcm_ui (mpz_t r, const mpz_t u, unsigned long v)
{
  if (v == 0 || u->_mp_size == 0)
    {
      r->_mp_size = 0;
      return;
    }

  v /= mpz_gcd_ui (NULL, u, v);
  mpz_mul_ui (r, u, v);

  mpz_abs (r, r);
}

int
mpz_invert (mpz_t r, const mpz_t u, const mpz_t m)
{
  mpz_t g, tr;
  int invertible;

  if (u->_mp_size == 0 || mpz_cmpabs_ui (m, 1) <= 0)
    return 0;

  mpz_init (g);
  mpz_init (tr);

  mpz_gcdext (g, tr, NULL, u, m);
  invertible = (mpz_cmp_ui (g, 1) == 0);

  if (invertible)
    {
      if (tr->_mp_size < 0)
	{
	  if (m->_mp_size >= 0)
	    mpz_add (tr, tr, m);
	  else
	    mpz_sub (tr, tr, m);
	}
      mpz_swap (r, tr);
    }

  mpz_clear (g);
  mpz_clear (tr);
  return invertible;
}


/* Higher level operations (sqrt, pow and root) */

void
mpz_pow_ui (mpz_t r, const mpz_t b, unsigned long e)
{
  unsigned long bit;
  mpz_t tr;
  mpz_init_set_ui (tr, 1);

  bit = GMP_ULONG_HIGHBIT;
  do
    {
      mpz_mul (tr, tr, tr);
      if (e & bit)
	mpz_mul (tr, tr, b);
      bit >>= 1;
    }
  while (bit > 0);

  mpz_swap (r, tr);
  mpz_clear (tr);
}

void
mpz_ui_pow_ui (mpz_t r, unsigned long blimb, unsigned long e)
{
  mpz_t b;
  mpz_init_set_ui (b, blimb);
  mpz_pow_ui (r, b, e);
  mpz_clear (b);
}

void
mpz_powm (mpz_t r, const mpz_t b, const mpz_t e, const mpz_t m)
{
  mpz_t tr;
  mpz_t base;
  mp_size_t en, mn;
  mp_srcptr mp;
  struct gmp_div_inverse minv;
  unsigned shift;
  mp_ptr tp = NULL;

  en = GMP_ABS (e->_mp_size);
  mn = GMP_ABS (m->_mp_size);
  if (mn == 0)
    gmp_die ("mpz_powm: Zero modulo.");

  if (en == 0)
    {
      mpz_set_ui (r, 1);
      return;
    }

  mp = m->_mp_d;
  mpn_div_qr_invert (&minv, mp, mn);
  shift = minv.shift;

  if (shift > 0)
    {
      /* To avoid shifts, we do all our reductions, except the final
	 one, using a *normalized* m. */
      minv.shift = 0;

      tp = gmp_xalloc_limbs (mn);
      gmp_assert_nocarry (mpn_lshift (tp, mp, mn, shift));
      mp = tp;
    }

  mpz_init (base);

  if (e->_mp_size < 0)
    {
      if (!mpz_invert (base, b, m))
	gmp_die ("mpz_powm: Negative exponent and non-invertible base.");
    }
  else
    {
      mp_size_t bn;
      mpz_abs (base, b);

      bn = base->_mp_size;
      if (bn >= mn)
	{
	  mpn_div_qr_preinv (NULL, base->_mp_d, base->_mp_size, mp, mn, &minv);
	  bn = mn;
	}

      /* We have reduced the absolute value. Now take care of the
	 sign. Note that we get zero represented non-canonically as
	 m. */
      if (b->_mp_size < 0)
	{
	  mp_ptr bp = MPZ_REALLOC (base, mn);
	  gmp_assert_nocarry (mpn_sub (bp, mp, mn, bp, bn));
	  bn = mn;
	}
      base->_mp_size = mpn_normalized_size (base->_mp_d, bn);
    }
  mpz_init_set_ui (tr, 1);

  while (en-- > 0)
    {
      mp_limb_t w = e->_mp_d[en];
      mp_limb_t bit;

      bit = GMP_LIMB_HIGHBIT;
      do
	{
	  mpz_mul (tr, tr, tr);
	  if (w & bit)
	    mpz_mul (tr, tr, base);
	  if (tr->_mp_size > mn)
	    {
	      mpn_div_qr_preinv (NULL, tr->_mp_d, tr->_mp_size, mp, mn, &minv);
	      tr->_mp_size = mpn_normalized_size (tr->_mp_d, mn);
	    }
	  bit >>= 1;
	}
      while (bit > 0);
    }

  /* Final reduction */
  if (tr->_mp_size >= mn)
    {
      minv.shift = shift;
      mpn_div_qr_preinv (NULL, tr->_mp_d, tr->_mp_size, mp, mn, &minv);
      tr->_mp_size = mpn_normalized_size (tr->_mp_d, mn);
    }
  if (tp)
    gmp_free (tp);

  mpz_swap (r, tr);
  mpz_clear (tr);
  mpz_clear (base);
}

void
mpz_powm_ui (mpz_t r, const mpz_t b, unsigned long elimb, const mpz_t m)
{
  mpz_t e;
  mpz_init_set_ui (e, elimb);
  mpz_powm (r, b, e, m);
  mpz_clear (e);
}

/* x=trunc(y^(1/z)), r=y-x^z */
void
mpz_rootrem (mpz_t x, mpz_t r, const mpz_t y, unsigned long z)
{
  int sgn;
  mpz_t t, u;

  sgn = y->_mp_size < 0;
  if ((~z & sgn) != 0)
    gmp_die ("mpz_rootrem: Negative argument, with even root.");
  if (z == 0)
    gmp_die ("mpz_rootrem: Zeroth root.");

  if (mpz_cmpabs_ui (y, 1) <= 0) {
    if (x)
      mpz_set (x, y);
    if (r)
      r->_mp_size = 0;
    return;
  }

  mpz_init (u);
  {
    mp_bitcnt_t tb;
    tb = mpz_sizeinbase (y, 2) / z + 1;
    mpz_init2 (t, tb);
    mpz_setbit (t, tb);
  }

  if (z == 2) /* simplify sqrt loop: z-1 == 1 */
    do {
      mpz_swap (u, t);			/* u = x */
      mpz_tdiv_q (t, y, u);		/* t = y/x */
      mpz_add (t, t, u);		/* t = y/x + x */
      mpz_tdiv_q_2exp (t, t, 1);	/* x'= (y/x + x)/2 */
    } while (mpz_cmpabs (t, u) < 0);	/* |x'| < |x| */
  else /* z != 2 */ {
    mpz_t v;

    mpz_init (v);
    if (sgn)
      mpz_neg (t, t);

    do {
      mpz_swap (u, t);			/* u = x */
      mpz_pow_ui (t, u, z - 1);		/* t = x^(z-1) */
      mpz_tdiv_q (t, y, t);		/* t = y/x^(z-1) */
      mpz_mul_ui (v, u, z - 1);		/* v = x*(z-1) */
      mpz_add (t, t, v);		/* t = y/x^(z-1) + x*(z-1) */
      mpz_tdiv_q_ui (t, t, z);		/* x'=(y/x^(z-1) + x*(z-1))/z */
    } while (mpz_cmpabs (t, u) < 0);	/* |x'| < |x| */

    mpz_clear (v);
  }

  if (r) {
    mpz_pow_ui (t, u, z);
    mpz_sub (r, y, t);
  }
  if (x)
    mpz_swap (x, u);
  mpz_clear (u);
  mpz_clear (t);
}

int
mpz_root (mpz_t x, const mpz_t y, unsigned long z)
{
  int res;
  mpz_t r;

  mpz_init (r);
  mpz_rootrem (x, r, y, z);
  res = r->_mp_size == 0;
  mpz_clear (r);

  return res;
}

/* Compute s = floor(sqrt(u)) and r = u - s^2. Allows r == NULL */
void
mpz_sqrtrem (mpz_t s, mpz_t r, const mpz_t u)
{
  mpz_rootrem (s, r, u, 2);
}

void
mpz_sqrt (mpz_t s, const mpz_t u)
{
  mpz_rootrem (s, NULL, u, 2);
}

int
mpz_perfect_square_p (const mpz_t u)
{
  if (u->_mp_size <= 0)
    return (u->_mp_size == 0);
  else
    return mpz_root (NULL, u, 2);
}

int
mpn_perfect_square_p (mp_srcptr p, mp_size_t n)
{
  mpz_t t;

  assert (n > 0);
  assert (p [n-1] != 0);
  return mpz_root (NULL, mpz_roinit_n (t, p, n), 2);
}

mp_size_t
mpn_sqrtrem (mp_ptr sp, mp_ptr rp, mp_srcptr p, mp_size_t n)
{
  mpz_t s, r, u;
  mp_size_t res;

  assert (n > 0);
  assert (p [n-1] != 0);

  mpz_init (r);
  mpz_init (s);
  mpz_rootrem (s, r, mpz_roinit_n (u, p, n), 2);

  assert (s->_mp_size == (n+1)/2);
  mpn_copyd (sp, s->_mp_d, s->_mp_size);
  mpz_clear (s);
  res = r->_mp_size;
  if (rp)
    mpn_copyd (rp, r->_mp_d, res);
  mpz_clear (r);
  return res;
}

/* Combinatorics */

void
mpz_fac_ui (mpz_t x, unsigned long n)
{
  mpz_set_ui (x, n + (n == 0));
  for (;n > 2;)
    mpz_mul_ui (x, x, --n);
}

void
mpz_bin_uiui (mpz_t r, unsigned long n, unsigned long k)
{
  mpz_t t;

  mpz_set_ui (r, k <= n);

  if (k > (n >> 1))
    k = (k <= n) ? n - k : 0;

  mpz_init (t);
  mpz_fac_ui (t, k);

  for (; k > 0; k--)
      mpz_mul_ui (r, r, n--);

  mpz_divexact (r, r, t);
  mpz_clear (t);
}


/* Primality testing */
static int
gmp_millerrabin (const mpz_t n, const mpz_t nm1, mpz_t y,
		 const mpz_t q, mp_bitcnt_t k)
{
  assert (k > 0);

  /* Caller must initialize y to the base. */
  mpz_powm (y, y, q, n);

  if (mpz_cmp_ui (y, 1) == 0 || mpz_cmp (y, nm1) == 0)
    return 1;

  while (--k > 0)
    {
      mpz_powm_ui (y, y, 2, n);
      if (mpz_cmp (y, nm1) == 0)
	return 1;
      /* y == 1 means that the previous y was a non-trivial square root
	 of 1 (mod n). y == 0 means that n is a power of the base.
	 In either case, n is not prime. */
      if (mpz_cmp_ui (y, 1) <= 0)
	return 0;
    }
  return 0;
}

/* This product is 0xc0cfd797, and fits in 32 bits. */
#define GMP_PRIME_PRODUCT \
  (3UL*5UL*7UL*11UL*13UL*17UL*19UL*23UL*29UL)

/* Bit (p+1)/2 is set, for each odd prime <= 61 */
#define GMP_PRIME_MASK 0xc96996dcUL

int
mpz_probab_prime_p (const mpz_t n, int reps)
{
  mpz_t nm1;
  mpz_t q;
  mpz_t y;
  mp_bitcnt_t k;
  int is_prime;
  int j;

  /* Note that we use the absolute value of n only, for compatibility
     with the real GMP. */
  if (mpz_even_p (n))
    return (mpz_cmpabs_ui (n, 2) == 0) ? 2 : 0;

  /* Above test excludes n == 0 */
  assert (n->_mp_size != 0);

  if (mpz_cmpabs_ui (n, 64) < 0)
    return (GMP_PRIME_MASK >> (n->_mp_d[0] >> 1)) & 2;

  if (mpz_gcd_ui (NULL, n, GMP_PRIME_PRODUCT) != 1)
    return 0;

  /* All prime factors are >= 31. */
  if (mpz_cmpabs_ui (n, 31*31) < 0)
    return 2;

  /* Use Miller-Rabin, with a deterministic sequence of bases, a[j] =
     j^2 + j + 41 using Euler's polynomial. We potentially stop early,
     if a[j] >= n - 1. Since n >= 31*31, this can happen only if reps >
     30 (a[30] == 971 > 31*31 == 961). */

  mpz_init (nm1);
  mpz_init (q);
  mpz_init (y);

  /* Find q and k, where q is odd and n = 1 + 2**k * q.  */
  nm1->_mp_size = mpz_abs_sub_ui (nm1, n, 1);
  k = mpz_scan1 (nm1, 0);
  mpz_tdiv_q_2exp (q, nm1, k);

  for (j = 0, is_prime = 1; is_prime & (j < reps); j++)
    {
      mpz_set_ui (y, (unsigned long) j*j+j+41);
      if (mpz_cmp (y, nm1) >= 0)
	{
	  /* Don't try any further bases. This "early" break does not affect
	     the result for any reasonable reps value (<=5000 was tested) */
	  assert (j >= 30);
	  break;
	}
      is_prime = gmp_millerrabin (n, nm1, y, q, k);
    }
  mpz_clear (nm1);
  mpz_clear (q);
  mpz_clear (y);

  return is_prime;
}


/* Logical operations and bit manipulation. */

/* Numbers are treated as if represented in two's complement (and
   infinitely sign extended). For a negative values we get the two's
   complement from -x = ~x + 1, where ~ is bitwise complement.
   Negation transforms

     xxxx10...0

   into

     yyyy10...0

   where yyyy is the bitwise complement of xxxx. So least significant
   bits, up to and including the first one bit, are unchanged, and
   the more significant bits are all complemented.

   To change a bit from zero to one in a negative number, subtract the
   corresponding power of two from the absolute value. This can never
   underflow. To change a bit from one to zero, add the corresponding
   power of two, and this might overflow. E.g., if x = -001111, the
   two's complement is 110001. Clearing the least significant bit, we
   get two's complement 110000, and -010000. */

int
mpz_tstbit (const mpz_t d, mp_bitcnt_t bit_index)
{
  mp_size_t limb_index;
  unsigned shift;
  mp_size_t ds;
  mp_size_t dn;
  mp_limb_t w;
  int bit;

  ds = d->_mp_size;
  dn = GMP_ABS (ds);
  limb_index = bit_index / GMP_LIMB_BITS;
  if (limb_index >= dn)
    return ds < 0;

  shift = bit_index % GMP_LIMB_BITS;
  w = d->_mp_d[limb_index];
  bit = (w >> shift) & 1;

  if (ds < 0)
    {
      /* d < 0. Check if any of the bits below is set: If so, our bit
	 must be complemented. */
      if (shift > 0 && (w << (GMP_LIMB_BITS - shift)) > 0)
	return bit ^ 1;
      while (limb_index-- > 0)
	if (d->_mp_d[limb_index] > 0)
	  return bit ^ 1;
    }
  return bit;
}

static void
mpz_abs_add_bit (mpz_t d, mp_bitcnt_t bit_index)
{
  mp_size_t dn, limb_index;
  mp_limb_t bit;
  mp_ptr dp;

  dn = GMP_ABS (d->_mp_size);

  limb_index = bit_index / GMP_LIMB_BITS;
  bit = (mp_limb_t) 1 << (bit_index % GMP_LIMB_BITS);

  if (limb_index >= dn)
    {
      mp_size_t i;
      /* The bit should be set outside of the end of the number.
	 We have to increase the size of the number. */
      dp = MPZ_REALLOC (d, limb_index + 1);

      dp[limb_index] = bit;
      for (i = dn; i < limb_index; i++)
	dp[i] = 0;
      dn = limb_index + 1;
    }
  else
    {
      mp_limb_t cy;

      dp = d->_mp_d;

      cy = mpn_add_1 (dp + limb_index, dp + limb_index, dn - limb_index, bit);
      if (cy > 0)
	{
	  dp = MPZ_REALLOC (d, dn + 1);
	  dp[dn++] = cy;
	}
    }

  d->_mp_size = (d->_mp_size < 0) ? - dn : dn;
}

static void
mpz_abs_sub_bit (mpz_t d, mp_bitcnt_t bit_index)
{
  mp_size_t dn, limb_index;
  mp_ptr dp;
  mp_limb_t bit;

  dn = GMP_ABS (d->_mp_size);
  dp = d->_mp_d;

  limb_index = bit_index / GMP_LIMB_BITS;
  bit = (mp_limb_t) 1 << (bit_index % GMP_LIMB_BITS);

  assert (limb_index < dn);

  gmp_assert_nocarry (mpn_sub_1 (dp + limb_index, dp + limb_index,
				 dn - limb_index, bit));
  dn -= (dp[dn-1] == 0);
  d->_mp_size = (d->_mp_size < 0) ? - dn : dn;
}

void
mpz_setbit (mpz_t d, mp_bitcnt_t bit_index)
{
  if (!mpz_tstbit (d, bit_index))
    {
      if (d->_mp_size >= 0)
	mpz_abs_add_bit (d, bit_index);
      else
	mpz_abs_sub_bit (d, bit_index);
    }
}

void
mpz_clrbit (mpz_t d, mp_bitcnt_t bit_index)
{
  if (mpz_tstbit (d, bit_index))
    {
      if (d->_mp_size >= 0)
	mpz_abs_sub_bit (d, bit_index);
      else
	mpz_abs_add_bit (d, bit_index);
    }
}

void
mpz_combit (mpz_t d, mp_bitcnt_t bit_index)
{
  if (mpz_tstbit (d, bit_index) ^ (d->_mp_size < 0))
    mpz_abs_sub_bit (d, bit_index);
  else
    mpz_abs_add_bit (d, bit_index);
}

void
mpz_com (mpz_t r, const mpz_t u)
{
  mpz_neg (r, u);
  mpz_sub_ui (r, r, 1);
}

void
mpz_and (mpz_t r, const mpz_t u, const mpz_t v)
{
  mp_size_t un, vn, rn, i;
  mp_ptr up, vp, rp;

  mp_limb_t ux, vx, rx;
  mp_limb_t uc, vc, rc;
  mp_limb_t ul, vl, rl;

  un = GMP_ABS (u->_mp_size);
  vn = GMP_ABS (v->_mp_size);
  if (un < vn)
    {
      MPZ_SRCPTR_SWAP (u, v);
      MP_SIZE_T_SWAP (un, vn);
    }
  if (vn == 0)
    {
      r->_mp_size = 0;
      return;
    }

  uc = u->_mp_size < 0;
  vc = v->_mp_size < 0;
  rc = uc & vc;

  ux = -uc;
  vx = -vc;
  rx = -rc;

  /* If the smaller input is positive, higher limbs don't matter. */
  rn = vx ? un : vn;

  rp = MPZ_REALLOC (r, rn + rc);

  up = u->_mp_d;
  vp = v->_mp_d;

  i = 0;
  do
    {
      ul = (up[i] ^ ux) + uc;
      uc = ul < uc;

      vl = (vp[i] ^ vx) + vc;
      vc = vl < vc;

      rl = ( (ul & vl) ^ rx) + rc;
      rc = rl < rc;
      rp[i] = rl;
    }
  while (++i < vn);
  assert (vc == 0);

  for (; i < rn; i++)
    {
      ul = (up[i] ^ ux) + uc;
      uc = ul < uc;

      rl = ( (ul & vx) ^ rx) + rc;
      rc = rl < rc;
      rp[i] = rl;
    }
  if (rc)
    rp[rn++] = rc;
  else
    rn = mpn_normalized_size (rp, rn);

  r->_mp_size = rx ? -rn : rn;
}

void
mpz_ior (mpz_t r, const mpz_t u, const mpz_t v)
{
  mp_size_t un, vn, rn, i;
  mp_ptr up, vp, rp;

  mp_limb_t ux, vx, rx;
  mp_limb_t uc, vc, rc;
  mp_limb_t ul, vl, rl;

  un = GMP_ABS (u->_mp_size);
  vn = GMP_ABS (v->_mp_size);
  if (un < vn)
    {
      MPZ_SRCPTR_SWAP (u, v);
      MP_SIZE_T_SWAP (un, vn);
    }
  if (vn == 0)
    {
      mpz_set (r, u);
      return;
    }

  uc = u->_mp_size < 0;
  vc = v->_mp_size < 0;
  rc = uc | vc;

  ux = -uc;
  vx = -vc;
  rx = -rc;

  /* If the smaller input is negative, by sign extension higher limbs
     don't matter. */
  rn = vx ? vn : un;

  rp = MPZ_REALLOC (r, rn + rc);

  up = u->_mp_d;
  vp = v->_mp_d;

  i = 0;
  do
    {
      ul = (up[i] ^ ux) + uc;
      uc = ul < uc;

      vl = (vp[i] ^ vx) + vc;
      vc = vl < vc;

      rl = ( (ul | vl) ^ rx) + rc;
      rc = rl < rc;
      rp[i] = rl;
    }
  while (++i < vn);
  assert (vc == 0);

  for (; i < rn; i++)
    {
      ul = (up[i] ^ ux) + uc;
      uc = ul < uc;

      rl = ( (ul | vx) ^ rx) + rc;
      rc = rl < rc;
      rp[i] = rl;
    }
  if (rc)
    rp[rn++] = rc;
  else
    rn = mpn_normalized_size (rp, rn);

  r->_mp_size = rx ? -rn : rn;
}

void
mpz_xor (mpz_t r, const mpz_t u, const mpz_t v)
{
  mp_size_t un, vn, i;
  mp_ptr up, vp, rp;

  mp_limb_t ux, vx, rx;
  mp_limb_t uc, vc, rc;
  mp_limb_t ul, vl, rl;

  un = GMP_ABS (u->_mp_size);
  vn = GMP_ABS (v->_mp_size);
  if (un < vn)
    {
      MPZ_SRCPTR_SWAP (u, v);
      MP_SIZE_T_SWAP (un, vn);
    }
  if (vn == 0)
    {
      mpz_set (r, u);
      return;
    }

  uc = u->_mp_size < 0;
  vc = v->_mp_size < 0;
  rc = uc ^ vc;

  ux = -uc;
  vx = -vc;
  rx = -rc;

  rp = MPZ_REALLOC (r, un + rc);

  up = u->_mp_d;
  vp = v->_mp_d;

  i = 0;
  do
    {
      ul = (up[i] ^ ux) + uc;
      uc = ul < uc;

      vl = (vp[i] ^ vx) + vc;
      vc = vl < vc;

      rl = (ul ^ vl ^ rx) + rc;
      rc = rl < rc;
      rp[i] = rl;
    }
  while (++i < vn);
  assert (vc == 0);

  for (; i < un; i++)
    {
      ul = (up[i] ^ ux) + uc;
      uc = ul < uc;

      rl = (ul ^ ux) + rc;
      rc = rl < rc;
      rp[i] = rl;
    }
  if (rc)
    rp[un++] = rc;
  else
    un = mpn_normalized_size (rp, un);

  r->_mp_size = rx ? -un : un;
}

static unsigned
gmp_popcount_limb (mp_limb_t x)
{
  unsigned c;

  /* Do 16 bits at a time, to avoid limb-sized constants. */
  for (c = 0; x > 0; x >>= 16)
    {
      unsigned w = ((x >> 1) & 0x5555) + (x & 0x5555);
      w = ((w >> 2) & 0x3333) + (w & 0x3333);
      w = ((w >> 4) & 0x0f0f) + (w & 0x0f0f);
      w = (w >> 8) + (w & 0x00ff);
      c += w;
    }
  return c;
}

mp_bitcnt_t
mpn_popcount (mp_srcptr p, mp_size_t n)
{
  mp_size_t i;
  mp_bitcnt_t c;

  for (c = 0, i = 0; i < n; i++)
    c += gmp_popcount_limb (p[i]);

  return c;
}

mp_bitcnt_t
mpz_popcount (const mpz_t u)
{
  mp_size_t un;

  un = u->_mp_size;

  if (un < 0)
    return ~(mp_bitcnt_t) 0;

  return mpn_popcount (u->_mp_d, un);
}

mp_bitcnt_t
mpz_hamdist (const mpz_t u, const mpz_t v)
{
  mp_size_t un, vn, i;
  mp_limb_t uc, vc, ul, vl, comp;
  mp_srcptr up, vp;
  mp_bitcnt_t c;

  un = u->_mp_size;
  vn = v->_mp_size;

  if ( (un ^ vn) < 0)
    return ~(mp_bitcnt_t) 0;

  comp = - (uc = vc = (un < 0));
  if (uc)
    {
      assert (vn < 0);
      un = -un;
      vn = -vn;
    }

  up = u->_mp_d;
  vp = v->_mp_d;

  if (un < vn)
    MPN_SRCPTR_SWAP (up, un, vp, vn);

  for (i = 0, c = 0; i < vn; i++)
    {
      ul = (up[i] ^ comp) + uc;
      uc = ul < uc;

      vl = (vp[i] ^ comp) + vc;
      vc = vl < vc;

      c += gmp_popcount_limb (ul ^ vl);
    }
  assert (vc == 0);

  for (; i < un; i++)
    {
      ul = (up[i] ^ comp) + uc;
      uc = ul < uc;

      c += gmp_popcount_limb (ul ^ comp);
    }

  return c;
}

mp_bitcnt_t
mpz_scan1 (const mpz_t u, mp_bitcnt_t starting_bit)
{
  mp_ptr up;
  mp_size_t us, un, i;
  mp_limb_t limb, ux;

  us = u->_mp_size;
  un = GMP_ABS (us);
  i = starting_bit / GMP_LIMB_BITS;

  /* Past the end there's no 1 bits for u>=0, or an immediate 1 bit
     for u<0. Notice this test picks up any u==0 too. */
  if (i >= un)
    return (us >= 0 ? ~(mp_bitcnt_t) 0 : starting_bit);

  up = u->_mp_d;
  ux = 0;
  limb = up[i];

  if (starting_bit != 0)
    {
      if (us < 0)
	{
	  ux = mpn_zero_p (up, i);
	  limb = ~ limb + ux;
	  ux = - (mp_limb_t) (limb >= ux);
	}

      /* Mask to 0 all bits before starting_bit, thus ignoring them. */
      limb &= (GMP_LIMB_MAX << (starting_bit % GMP_LIMB_BITS));
    }

  return mpn_common_scan (limb, i, up, un, ux);
}

mp_bitcnt_t
mpz_scan0 (const mpz_t u, mp_bitcnt_t starting_bit)
{
  mp_ptr up;
  mp_size_t us, un, i;
  mp_limb_t limb, ux;

  us = u->_mp_size;
  ux = - (mp_limb_t) (us >= 0);
  un = GMP_ABS (us);
  i = starting_bit / GMP_LIMB_BITS;

  /* When past end, there's an immediate 0 bit for u>=0, or no 0 bits for
     u<0.  Notice this test picks up all cases of u==0 too. */
  if (i >= un)
    return (ux ? starting_bit : ~(mp_bitcnt_t) 0);

  up = u->_mp_d;
  limb = up[i] ^ ux;

  if (ux == 0)
    limb -= mpn_zero_p (up, i); /* limb = ~(~limb + zero_p) */

  /* Mask all bits before starting_bit, thus ignoring them. */
  limb &= (GMP_LIMB_MAX << (starting_bit % GMP_LIMB_BITS));

  return mpn_common_scan (limb, i, up, un, ux);
}


/* MPZ base conversion. */

size_t
mpz_sizeinbase (const mpz_t u, int base)
{
  mp_size_t un;
  mp_srcptr up;
  mp_ptr tp;
  mp_bitcnt_t bits;
  struct gmp_div_inverse bi;
  size_t ndigits;

  assert (base >= 2);
  assert (base <= 36);

  un = GMP_ABS (u->_mp_size);
  if (un == 0)
    return 1;

  up = u->_mp_d;

  bits = (un - 1) * GMP_LIMB_BITS + mpn_limb_size_in_base_2 (up[un-1]);
  switch (base)
    {
    case 2:
      return bits;
    case 4:
      return (bits + 1) / 2;
    case 8:
      return (bits + 2) / 3;
    case 16:
      return (bits + 3) / 4;
    case 32:
      return (bits + 4) / 5;
      /* FIXME: Do something more clever for the common case of base
	 10. */
    }

  tp = gmp_xalloc_limbs (un);
  mpn_copyi (tp, up, un);
  mpn_div_qr_1_invert (&bi, base);

  ndigits = 0;
  do
    {
      ndigits++;
      mpn_div_qr_1_preinv (tp, tp, un, &bi);
      un -= (tp[un-1] == 0);
    }
  while (un > 0);

  gmp_free (tp);
  return ndigits;
}

char *
mpz_get_str (char *sp, int base, const mpz_t u)
{
  unsigned bits;
  const char *digits;
  mp_size_t un;
  size_t i, sn;

  if (base >= 0)
    {
      digits = "0123456789abcdefghijklmnopqrstuvwxyz";
    }
  else
    {
      base = -base;
      digits = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    }
  if (base <= 1)
    base = 10;
  if (base > 36)
    return NULL;

  sn = 1 + mpz_sizeinbase (u, base);
  if (!sp)
    sp = gmp_xalloc (1 + sn);

  un = GMP_ABS (u->_mp_size);

  if (un == 0)
    {
      sp[0] = '0';
      sp[1] = '\0';
      return sp;
    }

  i = 0;

  if (u->_mp_size < 0)
    sp[i++] = '-';

  bits = mpn_base_power_of_two_p (base);

  if (bits)
    /* Not modified in this case. */
    sn = i + mpn_get_str_bits ((unsigned char *) sp + i, bits, u->_mp_d, un);
  else
    {
      struct mpn_base_info info;
      mp_ptr tp;

      mpn_get_base_info (&info, base);
      tp = gmp_xalloc_limbs (un);
      mpn_copyi (tp, u->_mp_d, un);

      sn = i + mpn_get_str_other ((unsigned char *) sp + i, base, &info, tp, un);
      gmp_free (tp);
    }

  for (; i < sn; i++)
    sp[i] = digits[(unsigned char) sp[i]];

  sp[sn] = '\0';
  return sp;
}

int
mpz_set_str (mpz_t r, const char *sp, int base)
{
  unsigned bits;
  mp_size_t rn, alloc;
  mp_ptr rp;
  size_t sn;
  int sign;
  unsigned char *dp;
  assert (base == 0 || (base >= 2 && base <= 36));
  while (isspace( (unsigned char) *sp))
    sp++;
  sign = (*sp == '-');
  sp += sign;

  if (base == 0)
    {
      if (*sp == '0')
	{
	  sp++;
	  if (*sp == 'x' || *sp == 'X')
	    {
	      base = 16;
	      sp++;
	    }
	  else if (*sp == 'b' || *sp == 'B')
	    {
	      base = 2;
	      sp++;
	    }
	  else
	    base = 8;
	}
      else
	base = 10;
    }

  sn = strlen (sp);
  dp = gmp_xalloc (sn + (sn == 0));

  for (sn = 0; *sp; sp++)
    {
      unsigned digit;

      if (isspace ((unsigned char) *sp))
	continue;
      if (*sp >= '0' && *sp <= '9')
	digit = *sp - '0';
      else if (*sp >= 'a' && *sp <= 'z')
	digit = *sp - 'a' + 10;
      else if (*sp >= 'A' && *sp <= 'Z')
	digit = *sp - 'A' + 10;
      else
	digit = base; /* fail */

      if (digit >= base)
	{
	  gmp_free (dp);
	  r->_mp_size = 0;
	  return -1;
	}

      dp[sn++] = digit;
    }
  bits = mpn_base_power_of_two_p (base);

  if (bits > 0)
    {
      alloc = (sn * bits + GMP_LIMB_BITS - 1) / GMP_LIMB_BITS;
      rp = MPZ_REALLOC (r, alloc);
      rn = mpn_set_str_bits (rp, dp, sn, bits);
    }
  else
    {
      struct mpn_base_info info;
      mpn_get_base_info (&info, base);
      alloc = (sn + info.exp - 1) / info.exp;
      rp = MPZ_REALLOC (r, alloc);
      rn = mpn_set_str_other (rp, dp, sn, base, &info);
    }
  assert (rn <= alloc);
  gmp_free (dp);
  r->_mp_size = sign ? - rn : rn;

  return 0;
}

int
mpz_init_set_str (mpz_t r, const char *sp, int base)
{
  mpz_init (r);
  return mpz_set_str (r, sp, base);
}

size_t
mpz_out_str (FILE *stream, int base, const mpz_t x)
{
  char *str;
  size_t len;

  str = mpz_get_str (NULL, base, x);
  len = strlen (str);
  len = fwrite (str, 1, len, stream);
  gmp_free (str);
  return len;
}


static int
gmp_detect_endian (void)
{
  static const int i = 2;
  const unsigned char *p = (const unsigned char *) &i;
  return 1 - *p;
}

/* Import and export. Does not support nails. */
void
mpz_import (mpz_t r, size_t count, int order, size_t size, int endian,
	    size_t nails, const void *src)
{
  const unsigned char *p;
  ptrdiff_t word_step;
  mp_ptr rp;
  mp_size_t rn;

  /* The current (partial) limb. */
  mp_limb_t limb;
  /* The number of bytes already copied to this limb (starting from
     the low end). */
  size_t bytes;
  /* The index where the limb should be stored, when completed. */
  mp_size_t i;

  if (nails != 0)
    gmp_die ("mpz_import: Nails not supported.");

  assert (order == 1 || order == -1);
  assert (endian >= -1 && endian <= 1);

  if (endian == 0)
    endian = gmp_detect_endian ();

  p = (unsigned char *) src;

  word_step = (order != endian) ? 2 * size : 0;

  /* Process bytes from the least significant end, so point p at the
     least significant word. */
  if (order == 1)
    {
      p += size * (count - 1);
      word_step = - word_step;
    }

  /* And at least significant byte of that word. */
  if (endian == 1)
    p += (size - 1);

  rn = (size * count + sizeof(mp_limb_t) - 1) / sizeof(mp_limb_t);
  rp = MPZ_REALLOC (r, rn);

  for (limb = 0, bytes = 0, i = 0; count > 0; count--, p += word_step)
    {
      size_t j;
      for (j = 0; j < size; j++, p -= (ptrdiff_t) endian)
	{
	  limb |= (mp_limb_t) *p << (bytes++ * CHAR_BIT);
	  if (bytes == sizeof(mp_limb_t))
	    {
	      rp[i++] = limb;
	      bytes = 0;
	      limb = 0;
	    }
	}
    }
  assert (i + (bytes > 0) == rn);
  if (limb != 0)
    rp[i++] = limb;
  else
    i = mpn_normalized_size (rp, i);

  r->_mp_size = i;
}

void *
mpz_export (void *r, size_t *countp, int order, size_t size, int endian,
	    size_t nails, const mpz_t u)
{
  size_t count;
  mp_size_t un;

  if (nails != 0)
    gmp_die ("mpz_import: Nails not supported.");

  assert (order == 1 || order == -1);
  assert (endian >= -1 && endian <= 1);
  assert (size > 0 || u->_mp_size == 0);

  un = u->_mp_size;
  count = 0;
  if (un != 0)
    {
      size_t k;
      unsigned char *p;
      ptrdiff_t word_step;
      /* The current (partial) limb. */
      mp_limb_t limb;
      /* The number of bytes left to to in this limb. */
      size_t bytes;
      /* The index where the limb was read. */
      mp_size_t i;

      un = GMP_ABS (un);

      /* Count bytes in top limb. */
      limb = u->_mp_d[un-1];
      assert (limb != 0);

      k = 0;
      do {
	k++; limb >>= CHAR_BIT;
      } while (limb != 0);

      count = (k + (un-1) * sizeof (mp_limb_t) + size - 1) / size;

      if (!r)
	r = gmp_xalloc (count * size);

      if (endian == 0)
	endian = gmp_detect_endian ();

      p = (unsigned char *) r;

      word_step = (order != endian) ? 2 * size : 0;

      /* Process bytes from the least significant end, so point p at the
	 least significant word. */
      if (order == 1)
	{
	  p += size * (count - 1);
	  word_step = - word_step;
	}

      /* And at least significant byte of that word. */
      if (endian == 1)
	p += (size - 1);

      for (bytes = 0, i = 0, k = 0; k < count; k++, p += word_step)
	{
	  size_t j;
	  for (j = 0; j < size; j++, p -= (ptrdiff_t) endian)
	    {
	      if (bytes == 0)
		{
		  if (i < un)
		    limb = u->_mp_d[i++];
		  bytes = sizeof (mp_limb_t);
		}
	      *p = limb;
	      limb >>= CHAR_BIT;
	      bytes--;
	    }
	}
      assert (i == un);
      assert (k == count);
    }

  if (countp)
    *countp = count;

  return r;
}
#else
#include <gmp.h>
#endif
