import sys
import ebpf_c_code as ebpfcc
import ebpf_python_code as ebpfpy

if __name__ == "__main__":
	if len(sys.argv) < 2:
		print("sudo python3 ebpf_main.py [application_name]")
		sys.exit(0)

	print('make bpf code')
	ebpfCCode = ebpfcc.ebpfCCode()
	bpf_code = ebpfCCode.make_code()

	ebpfPythonCode = ebpfpy.ebpfPythonCode(bpf_code, sys.argv[1])
	ebpfPythonCode.start()
