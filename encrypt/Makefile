include ./config.mk

.PHONY : all binary check clean reallyclean test install uninstall

PLUGIN_NAME=mosquitto_message_encrypt
LINK_LIBS=-lgmssl -lmongoc-1.0 -lbson-1.0 -lmongocxx -lbsoncxx -lcairo
INCLUDE_DIRECTORIES=-I./include -I/usr/local/include/libmongoc-1.0 -I/usr/local/include/libbson-1.0 -I/usr/local/include/mongocxx/v_noabi -I/usr/local/include/bsoncxx/v_noabi -I/usr/local/include/gmssl
all : binary

binary : ${PLUGIN_NAME}.so

${PLUGIN_NAME}.so : ${PLUGIN_NAME}.cpp
	$(CROSS_COMPILE)$(CXX) $(PLUGIN_CPPFLAGS) $(PLUGIN_CFLAGS) $(LINK_LIBS) $(PLUGIN_LDFLAGS) $(INCLUDE_DIRECTORIES) -fPIC -shared $< -o $@

reallyclean : clean
clean:
	-rm -f *.o ${PLUGIN_NAME}.so *.gcda *.gcno

check: test
test:

install: ${PLUGIN_NAME}.so
	# Don't install, these are examples only.
	#$(INSTALL) -d "${DESTDIR}$(libdir)"
	#$(INSTALL) ${STRIP_OPTS} ${PLUGIN_NAME}.so "${DESTDIR}${libdir}/${PLUGIN_NAME}.so"

uninstall :
	-rm -f "${DESTDIR}${libdir}/${PLUGIN_NAME}.so"
