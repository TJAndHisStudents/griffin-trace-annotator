import os
import re
import sys
import struct
import math

# Validate the input arguments
if len(sys.argv) < 2:
	print 'Griffin Tracing Annotator'
	print '========================='
	print 'usage: python annotate_griffin_trace.py parsed_pt_log_file readelf_output [optional: violation_file]\n'
	print 'Readelfing a binary: `readelf --wide -s [binary]`\n'
	sys.exit(0)

# Set the default argument values
pt_log_output  = sys.argv[1]
readelf_output = sys.argv[2]

# Get the violations if needed
violation_file = ""
if len(sys.argv) == 4:
	violation_file = sys.argv[3]

def getFunctionsFromAddresses(readelf):
	func_map = {}

	for line in open(readelf):

		# Trim the left and right whitespace
		line = line.strip()

		# Require a certain format to the line - starts with number, :, space(s), 16 hex digits, space(s)
		valid_line = re.match('^\d+:\s+[0-9abcdef]{16}\s+', line)

		if valid_line != None:
			# Example line:
			#     27: 0000000000000000     0 FILE    LOCAL  DEFAULT  ABS crtstuff.c

			# Parse the line to retrieve the function name and address
			elements = re.split('\s+', line)
			address = elements[1].lstrip("0") # Remove leading zeros
			function = elements[-1] if (len(elements) > 7) else ''

			# If the address is empty after removing leading zeros, set to 0
			address = address if (len(address) > 0) else '0'

			if function:
				func_map[address] = function

			continue

	return func_map


def getViolationsFromAddresses(violations):
	violation_map = {}

	for line in open(violations):

		# Trim the left and right whitespace
		line = line.strip()

		# Require a certain format to the line - starts with 0 or 1, then space, 
		valid_line = re.match('^[01]\s[0-9abcdef]{6,}', line)

		if valid_line != None:
			# Example line:
			#     0 400644

			# Parse the line to retrieve the violation type and address
			elements       = re.split('\s+', line)
			violation_type = elements[0]
			address        = elements[1]

			if address:
				violation_map[address] = "Forward-Edge Violation" if violation_type == "0" else "Shadow Stack Violation"

	return violation_map


def annotate(log, func_map, violation_map = {}):
	output = ""

	for line in open(log):
		# Example line:
		#  block: 7ffff7aa9a9b

		# Trim the left and right whitespace
		cleaned_line = line.strip()

		# Require a certain format to the line - starts with number, :, space(s), 16 hex digits, space(s)
		valid_line = re.match('^block:\s+([0-9abcdef]+)$', cleaned_line)

		if valid_line != None:
			address = valid_line.group(1)

			# See if a function maps to this address
			function = func_map.get(address, None)

			# See if a violation maps to this address
			violation_type = violation_map.get(address, None)

			# Modify the line
			if function:
				line = line.rstrip() + ' : ' + function + '\r\n'

			# Include violation
			if violation_type:
				line = line.rstrip() + ' : ' + violation_type + '\r\n'

		output = output + line

	return output

if __name__ == '__main__':
	violation_map = {}
	func_map = getFunctionsFromAddresses(readelf_output)
	if (violation_file):
		violation_map = getViolationsFromAddresses(violation_file)
	annotated_output = annotate(pt_log_output, func_map, violation_map)
	print annotated_output
