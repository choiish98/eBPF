from bcc import BPF
import multiprocessing
import ctypes as ct
import logging

from threading import Thread
from queue import Queue
import time

class ebpfPythonCode:
	def __init__(self, bpf_code, app_name):
		self.bpf_code = bpf_code
		self.app_name = app_name

		self.b = BPF(text = self.bpf_code, cflags = ['-w', '-std=gnu99', '-DNUM_CPUS=%d' % multiprocessing.cpu_count()])

		self.e_array = self.b["e_array"]
		self.e_index = self.b["e_index"]
		self.e_array_size = 102400
		self.prev_idx = 0
		self.cur_idx = 0

		self.fp = open(app_name, "w")
		self.log_th = None
	
	def polling_data(self):
		while True:
			self.cur_idx = self.e_index.get(ct.c_uint(0))
			if self.cur_idx == None : continue
			self.cur_idx = self.cur_idx.value
			if self.prev_idx >= self.cur_idx : continue

			for idx in range(self.prev_idx, self.cur_idx + 1):
				idx = idx % self.e_array_size
				data = self.e_array[idx]
				self.fp.write(str(data.order) + " " + str(data.sec) + "." + str(data.usec)  + "\n")
				
			self.prev_idx = self.cur_idx
	
	def start(self):
		print("start")
		self.polling_data()
		self.fp.close()
