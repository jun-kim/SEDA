CONTIKI_PROJECT = pbc_gmp
all: $(CONTIKI_PROJECT)

UIP_CONF_IPV6=1
#CONTIKI_NO_NET=1
APPS += bkem
CONTIKI = ../..
CFLAGS += -I/home/user/include/ -I/home/user/include/pbc/ #-DNDEBUG
#LDFLAGS += -lm -lc
#CFLAGS += -ffunction-sections
#LDFLAGS += -Wl,--gc-sections,--undefined=_reset_vector__,--undefined=InterruptVectors,--undefined=_copy_data_init__,--undefined=_clear_bss_init__,--undefined=_end_of_init_
#CFLAGS += -DNDEBUG
MODULES += core/net/ipv6/multicast
#TARGET_LIBFILES += /home/user/lib/libpbc.a  
#TARGET_LIBFILES += /home/user/lib/libgmp.a
include $(CONTIKI)/Makefile.include
