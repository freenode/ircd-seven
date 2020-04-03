env apt install $(env cat DEPENDENCIES | env grep -v "^#")
