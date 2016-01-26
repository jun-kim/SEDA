// Boneh-Lynn-Shacham short signatures demo.
//
// See the PBC_sig library for a practical implementation.
//
// Ben Lynn
#include <pbc.h>
#include <pbc_test.h>

void dump_element_binary2(char* name, element_ptr e)
{
	char *buf = pbc_malloc(e->field->fixed_length_in_bytes +1);

//	element_printf("element= [%B]\n",e);
//	printf("[%s size=%d] \n",name,e->field->fixed_length_in_bytes);
	e->field->snprint(buf, e->field->fixed_length_in_bytes,e);
	printf("char %s[%d] = \"%s\";\n",name,e->field->fixed_length_in_bytes,buf);
	pbc_free(buf);
}


void dump_element_binary2_binary_compressed(char*name,element_ptr e)
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


void dump_element_binary2_binary2(char*name,element_ptr e)
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


int main(int argc, char **argv) {
  pairing_t pairing;
  element_t g, h;
  element_t public_key, sig;
  element_t secret_key;
  element_t temp1, temp2;

printf("GOGO \n");
  pbc_demo_pairing_init(pairing, argc, argv);

  element_init_G2(g, pairing);
  element_init_G2(public_key, pairing);
  element_init_G1(h, pairing);
  element_init_G1(sig, pairing);
  element_init_GT(temp1, pairing);
  element_init_GT(temp2, pairing);
  element_init_Zr(secret_key, pairing);

  printf("Short signature test\n");

  //generate system parameters
  element_random(g);
  element_printf("system parameter g = %B\n", g);
  dump_element_binary2("system parameter g",g);

  //generate private key
  element_random(secret_key);
  element_printf("private key = %B\n", secret_key);
  dump_element_binary2("system parameter g",g);
  //compute corresponding public key
  element_pow_zn(public_key, g, secret_key);
  element_printf("public key = %B\n", public_key);
  dump_element_binary2("system public g",public_key);
  //generate element from a hash
  //for toy pairings, should check that pairing(g, h) != 1
  element_from_hash(h, "hashofmessage", 13);
  element_printf("message hash = %B\n", h);
  dump_element_binary2("message hash",h);
  //h^secret_key is the signature
  //in real life: only output the first coordinate
  element_pow_zn(sig, h, secret_key);
  element_printf("signature = %B\n", sig);
  dump_element_binary2(" signature",sig);
  {
    int n = pairing_length_in_bytes_compressed_G1(pairing);
	int n2 = pairing_length_in_bytes_G1(pairing);
	
    //int n = element_length_in_bytes_compressed(sig);
    int i;
    unsigned char *data = pbc_malloc(n);

    element_to_bytes_compressed(data, sig);
    printf("compressed[%d,%d] = ",n,n2);
    for (i = 0; i < n; i++) {
      printf("%02X", data[i]);
    }
    printf("\n");

    element_from_bytes_compressed(sig, data);
    element_printf("decompressed = %B\n", sig);
  dump_element_binary2("decompressed",sig);
    pbc_free(data);
  }

  //verification part 1
  element_pairing(temp1, sig, g);
  element_printf("f(sig, g) = %B\n", temp1);
  dump_element_binary2("f(sig, g)",temp1);
  //verification part 2
  //should match above
  element_pairing(temp2, h, public_key);
  element_printf("f(message hash, public_key) = %B\n", temp2);
  dump_element_binary2("f(message hash, public_key)",temp2);
  if (!element_cmp(temp1, temp2)) {
    printf("signature verifies\n");
  } else {
    printf("*BUG* signature does not verify *BUG*\n");
  }

  {
    int n = pairing_length_in_bytes_x_only_G1(pairing);
    //int n = element_length_in_bytes_x_only(sig);
    int i;
    unsigned char *data = pbc_malloc(n);

    element_to_bytes_x_only(data, sig);
    printf("x-coord = ");
    for (i = 0; i < n; i++) {
      printf("%02X", data[i]);
    }
    printf("\n");

    element_from_bytes_x_only(sig, data);
    element_printf("de-x-ed = %B\n", sig);
  dump_element_binary2("de-x-ed",sig);	

    element_pairing(temp1, sig, g);
    if (!element_cmp(temp1, temp2)) {
      printf("signature verifies on first guess\n");
    } else {
      element_invert(temp1, temp1);
      if (!element_cmp(temp1, temp2)) {
        printf("signature verifies on second guess\n");
      } else {
        printf("*BUG* signature does not verify *BUG*\n");
      }
    }

    pbc_free(data);
  }

  //a random signature shouldn't verify
  element_random(sig);
  element_pairing(temp1, sig, g);
  if (element_cmp(temp1, temp2)) {
    printf("random signature doesn't verify\n");
  } else {
    printf("*BUG* random signature verifies *BUG*\n");
  }

  element_clear(sig);
  element_clear(public_key);
  element_clear(secret_key);
  element_clear(g);
  element_clear(h);
  element_clear(temp1);
  element_clear(temp2);
  pairing_clear(pairing);
  return 0;
}
