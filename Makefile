PLUGINS := auth encrypt

TARGETS := all clean

.PHONY: $(TARGETS) $(PLUGINS)
all: $(PLUGINS)
clean: $(PLUGINS)

$(PLUGINS):
	$(MAKE) -C $@ $(MAKECMDGOALS)
