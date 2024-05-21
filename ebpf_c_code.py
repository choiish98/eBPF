class ebpfCCode:
	def __init__(self):
		self.header = ""
		self.common = ""
		self.body = ""
		self.code = ""
		self.sentence = """
						index = array_index.lookup(&array_index_key);
                        if (index == NULL) e_index_val = 0;
                        else e_index_val = *index + 1;
                        e_index.update(&e_index_key, &e_index_val);
                        array_index.update(&array_index_key, &e_index_val);
						"""

		self.attach_common()
		self.attach_header()
		self.attach_body()

	def attach_common(self):
		self.common = """
			static inline void event_occur(int order, u64 sec, u64 usec, u32 e_index_val) {
				struct event_data data = {};

				data.order = order;
				data.sec = sec;
				data.usec = usec;

				e_index_val = e_index_val % ARRAY_SIZE;
				e_array.update(&e_index_val, &data);

				return;
			}
		"""

	def attach_header(self):
		self.header = """
			#include <linux/sched.h>
			#include <linux/mm.h>
			#include <uapi/linux/ptrace.h>
			#include <uapi/linux/bpf.h>
			#define ARRAY_SIZE 102400

			struct event_data {
				int order;			
				u64 sec;			
				u64 usec;
			};

			BPF_ARRAY(e_array, struct event_data, ARRAY_SIZE);
			BPF_TABLE("hash", u32, u32, e_index, 1);
			BPF_HASH(array_index, u32, u32);
		"""
	
	def attach_body(self):
		self.body = """
		    int kprobe__sswap_log_minor(struct pt_regs *ctx, int order, uint64_t ts) {
				u32 e_index_key = 0, array_index_key = 0, *index;
				u32 e_index_val;

				##common##
				event_occur(order, ts/1000, ts%1000/100, e_index_val);

				return 0;
			}
		"""
	
	def make_code(self):
		self.code += self.header
		self.code += self.common
		self.code += self.body

		self.code = self.code.replace("##common##", self.sentence)
		return self.code
