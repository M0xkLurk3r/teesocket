#! /usr/bin/env python
#coding=utf-8

import signal, sys, os
import time

do_write = False

def handler(sig, f):
	sys.stderr.write("Begin!\n")
	do_write = True
	try:
		target_file = open(sys.argv[1])
		while 1:
			data = target_file.read(32768)
			if not data:
				break
			sys.stdout.write(data)
	except IOError as err:
		print "Open file error:", err
	except Exception as err:
		print "Error:", err
	exit(0)

if __name__ == "__main__":
	if len(sys.argv) < 2:
		sys.stderr.write("Argument expected")
		exit(1)
	signal.signal(signal.SIGUSR1, handler)
	while 1:
		time.sleep(1)
		
	
