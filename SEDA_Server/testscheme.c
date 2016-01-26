#include "bkem.h"

#define BLACK   "\033[0;30;49m"
#define RED     "\x1b[0;31;49m"
#define GREEN   "\x1b[0;32;49m"
#define YELLOW  "\x1b[0;33;49m"
#define BLUE    "\x1b[0;34;49m"
#define MAGENTA "\x1b[0;35;49m"
#define CYAN    "\x1b[0;36;49m"
#define WHITE   "\x1b[0;37;49m"
#define DEFAULT "\x1b[0m"


#define DUMP_MODE 1 // DUMP pre calculate keys
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

///* compression
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
unsigned char enc[42] = {0x58,0x64,0x00,0xf3,0x54,0x07,0x96,0x46,0xb5,0xac,0x10,0x9c,0x2a,0x92,0x7f,0x50,0xcb,0xc7,0xe8,0xf5,0x8b,0x3b,0xe4,0xe7,0x38,0x0a,0x58,0xfe,0x41,0x3e,0x44,0xa5,0xfb,0x09,0xec,0x84,0x09,0xdf,0x32,0xe5,0x25,0x52};
unsigned char hdr_0[22] = {0x18,0x52,0x62,0x81,0x21,0xca,0x7f,0xed,0x31,0xa4,0xb2,0x1b,0xc6,0x76,0x7a,0x03,0xf1,0xe6,0x62,0x79,0x84,0x01};
unsigned char hdr_1[22] = {0x52,0xf0,0xba,0xba,0xd2,0xa4,0x02,0x41,0x36,0x4b,0x56,0xc9,0x7e,0xdb,0x89,0x63,0xbc,0x58,0xf0,0x41,0x53,0x00};

#if USE_COMPRESS
void set_element_binary_G1(element_t e, unsigned char *data,bkem_global_params_t gps)
{
	element_init_G1(e, gps->pairing);
//	for(i=0;i<e->field->fixed_length_in_bytes;i++) 		printf("%02x",data[i]); 	printf("};\n");
	element_from_bytes_compressed(e,data);
//	e->field->from_bytes(e,data);
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
//	dump_element_binary("pk_g",sys->PK->g);

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
	set_element_binary_GT(kp->K ,enc ,gps); // for checking purpose
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

    element_init_GT(den, gps->pairing);
    pairing_apply(den, temp, HDR[0], gps->pairing);
//	dump_element_binary("den",den);

    element_init_GT(K, gps->pairing);
    element_div(K, nom, den);

//	dump_element_binary("K",K);
	
    element_clear(temp);
    element_clear(nom);
    element_clear(den);

}
int main(int argc, const char *argv[]) {

	char name[128];
	if(argv[2] == '\0')
		sprintf(name,"a_test.param");
	else sprintf(name,"%s",argv[2]);
	
//	FILE *param = fopen("a_test.param", "r");
	FILE *param = fopen(name, "r");
	char buf[4096];
	fread(buf, 1, 4096, param);

	//printf("\nSystem setup Key\n\n");
	printf("FILE: %s\n",name);
	bkem_global_params_t gps;
	setup_global_system(&gps, (const char*) buf, (argc > 1) ? atoi(argv[1]) : 256);
//	printf("param = [%s] \n",buf);

	printf("Global System parameters: N = %d, A = %d, B = %d\n\n", gps->N, gps->A, gps->B);

	bkem_system_t sys;
	setup2(&sys, gps);
	set_pre_distributed_keys(sys, gps);

	//printf("\nTesting system\n\n");
	
	unsigned int c,k,j,i;
	for (c = 2; c <= gps->N; c*=2) {

			if (c >= 3) return;
	int S[c];
//	printf("\nTesting with S = [ ");
	for (k = 0; k < c; ++k) {
		S[k] = k;
	//	printf("%d ", k);
	}

//	printf("]\n\n");
	keypair_t keypair;
	get_encryption_key2(&keypair, S, c, sys, gps);
	element_t K;
	for (j = 0; j < gps->N; ++j) {
//		printf("c= %d, j= %d \n",c,j);
		
			get_decryption_key_pre(K, gps, S, c, j, sys->d_i[j], keypair->HDR, sys->PK);
			sprintf(buf,"Private key[%d]",j);
			dump_element_binary2(buf,sys->d_i[j]);
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
}

#else

#endif
