MZ = '\x4D\x5A'
FEED_FACE = '\xFE\xED\xFA\xCE'
FEED_FACF = '\xFE\xED\xFA\xCF'
ELF = '\x7F\x45\x4C\x46'

EXECUTABLE_PREFIXES = {
	MZ,
	FEED_FACE,
	FEED_FACF,
	ELF
}

def find_min_length(first_arr, second_arr):
	if len(first_arr) <= len(second_arr):
		return len(first_arr)
	return len(second_arr)

def starts_with_prefix(files_data_str, prefix):
	length_to_test = find_min_length(files_data_str, prefix)
	for i in range(length_to_test):
		if files_data_str[i] != prefix[i]:
			return False
	return True

def is_file_executable(files_data_str):
	for prefix in EXECUTABLE_PREFIXES:
		if starts_with_prefix(files_data_str, prefix):
			return True
	return False
