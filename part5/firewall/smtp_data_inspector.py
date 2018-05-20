import sys, string, struct, re, collections
from StringIO import StringIO


INFIMUM_PERCENTAGE_LINES_ENDING_WITH_SEMICOLON_IN_C_CODE = 0.20
INFIMUM_PERCENTAGE_SEMICOLON_FROM_TOATL_CHARS = 0.005 
INFIMUM_PERCENTAGE_TYPICAL_WORDS_FROM_TOATL_WORDS = 0.05
COMMON_CHAR_EVALUATION = 0.09
MINIMUM_ROWS_TO_EVALUATE = 2
MINIMUM_CHARACTERS_TO_EVALUATE = 500
ASSUME_CODE_VALUE = 0.97

#No matter what's the length of the data checked, if it includes those - it's probably C code:
C_EXPLICIT_COMBINATIONS = {
	"->", "==", "&&", "||",
	"#ifndef", "#define",
	"#include", "#endif",
}

#No matter what's the length of the data checked, if it includes those - it's probably C code:
C_EXPLICIT_KEYWORDS = {
	"enum",  "typedef","goto", "sizeof",
	"_Packed", "int", "else if", "break;",
	"do{", "ssize_t", "size_t", "NULL", 
	
}


#No matter what's the length of the data checked, if it includes those - it's probably C code:
C_EXPLICIT_FUNCTION_NAMES = {
	"printf(", "printk(", "free(", "kfree(",
	"close(", "open(", "strncpy(", "strcpy(",
	"strnlen(", "strlen(", "strcmp(", 
}


C_TYPICAL_KEYWORDS = {
	"auto", "else",	"long",	"switch",
	"break", "register", "case", "extern",
	"return", "union",  "struct", "bool",
	"char",	"float", "short", "unsigned",
	"const", "for", "signed", "void",
	"continue", "volatile", "do", "while",
	"default", "if", "static", "double",
	
}


C_TYPES  = {
	"int", "bool", "char", "float",
	"short", "long",  
}


COMMON_C_PATTERNS = {
	"(.*?)while[ \t\n\r\f\v]*\((.*?)\)[ \t\n\r\f\v]*\{(.*?)\}",	#"while" pattern
	"(.*?)if[ \t\n\r\f\v]*\((.*?)\)[ \t\n\r\f\v]*\{(.*?)\}",	#"if" pattern
	"(.*?)for[ \t\n\r\f\v]*\((.*?)\;(.*?)\;(.*?)\)[ \t\n\r\f\v]*\{(.*?)\}",	#"for" pattern
	"(.*?)\/\*(.*?)\*\/(.*?)",	#comments' pattern ( /*comment*/ )
	"\(\*(.*?)\)\.",	#accessing field: ( (*pointer_to_object). )
}

COMMON_C_CHARACTERS = {
	';', '{' , '}', '(', ')',
	'>', '<', '=', '!', '*',
	'-', '/', '&', '[', ']',
}

def is_explicit_c_word(word):
	"""
	Returns true if word is an explicit C code word.
	"""
	return word in C_EXPLICIT_KEYWORDS or word in C_EXPLICIT_COMBINATIONS or word in C_EXPLICIT_FUNCTION_NAMES


def is_typical_c_word(word):
	"""
	Returns true if word is a typical C code word.
	"""
	return word in C_TYPICAL_KEYWORDS or word in C_TYPES


def generate_array_patterns():
	array_patterns = set()
	for type_name in C_TYPES:
		pat = "(.*?)"+type_name+"\[(.*?)\](.*?)"
		array_patterns.add(pat)
	return array_patterns


def probability_according_to_semicolons(number_of_semicolons,number_of_rows_in_data, datas_length):
	"""
	Returns a probability [0,1] for the data to be C code according to the values of parameters provided.
	"""
	if number_of_rows_in_data>=MINIMUM_ROWS_TO_EVALUATE:
		if number_of_semicolons/float(number_of_rows_in_data) >= INFIMUM_PERCENTAGE_LINES_ENDING_WITH_SEMICOLON_IN_C_CODE:
			return 0.9
		if number_of_semicolons/float(datas_length) >= INFIMUM_PERCENTAGE_SEMICOLON_FROM_TOATL_CHARS:
			if datas_length>=MINIMUM_CHARACTERS_TO_EVALUATE:
				return 0.85
			return min(number_of_semicolons*0.5, 0.5)
	return min(number_of_semicolons, 0.3)


def probability_according_to_special_characters(character_appearances_dict, total_characters):
	
	do_not_count_chars = {'\n', ' ', '\t', '\r', '\f','\v'}
	common_char_counter = 0

	if total_characters == 0: 
		return 0

	total_char_counter = total_characters

	for common_char in COMMON_C_CHARACTERS:
		if common_char in character_appearances_dict:
			common_char_counter+=character_appearances_dict[common_char]

	for c in do_not_count_chars:
		if c in character_appearances_dict:
			total_char_counter-=character_appearances_dict[c]

	#print("Common char value is: {0}, total char counter is: {1}".format(common_char_counter,float(total_char_counter))) 
	#print("Common char evaluation is: {0}".format(common_char_counter/float(total_char_counter))) 
	if (common_char_counter/float(total_char_counter))>=COMMON_CHAR_EVALUATION:
		return 0.8
	return (common_char_counter/float(total_char_counter))*5 #Value returned will be < 0.09*5 = 0.45


def probability_according_to_words(file_data):
	explicit_words_counter = 0
	typical_words_counter = 0
	words_tested = 0
	
	words = re.split("[ \t\n\r\f\v]+", file_data)
	num_of_words = len(words)
	if num_of_words==0:
		return 0
	
	for word in words:
		if explicit_words_counter>=5:
			#print("Found 5 explicit words, ending test of probability_according_to_words(). value to be returned is:")
			#print((0.9+min(0.05,typical_words_counter/float(words_tested))))
			return 0.9+min(0.05,typical_words_counter/float(words_tested))
		if is_explicit_c_word(word):
			explicit_words_counter+=1
		elif is_typical_c_word(word):
			typical_words_counter+=1
		words_tested+=1

	#print "\nTotal words found:\nExplicit: [",explicit_words_counter,"] Typical: [",typical_words_counter,"]"," All words: [",num_of_words,"]"
	#print "Explicit percentage: ", explicit_words_counter/float(words_tested), " Typical percentage: ", typical_words_counter/float(words_tested) 
	
	if typical_words_counter/float(words_tested) >= INFIMUM_PERCENTAGE_TYPICAL_WORDS_FROM_TOATL_WORDS:
		enough_typical_words = 1
	else:
		enough_typical_words = 0

	if explicit_words_counter == 0:
		if enough_typical_words == 0:
			return 0
		else:
			return 0.4

	if  2<=explicit_words_counter<=4:
		return 0.7+0.15*enough_typical_words

	return 0.5+1*enough_typical_words



def is_data_c_code(file_data):
	
	#Creates a dictionary of <character, number of appearances of that character> based on file_data:
	all_characters_dict = collections.Counter(file_data)
	datas_characters = all_characters_dict.keys()
	probabilities = []


	if '\n' in datas_characters:
		number_of_rows_in_data = all_characters_dict['\n']
	else:
		number_of_rows_in_data = 0

	if ';' in datas_characters:
		number_of_semicolons = all_characters_dict[';']
	else:
		number_of_semicolons = 0


	probabilities.append(probability_according_to_words(file_data))
	probabilities.append(probability_according_to_semicolons(number_of_semicolons,number_of_rows_in_data, len(file_data)))

	if probabilities[0]>=0.9 and probabilities[1]>=0.85:
		return True

	probabilities.append(probability_according_to_special_characters(all_characters_dict, len(file_data)))




	#array_patterns = generate_array_patterns()




	
	

	#for k in all_characters_dict:
	#	print k, all_characters_dict[k]

	"""
	if '{' in datas_characters:
		print("\tNumber of '{{': {0}".format(all_characters_dict['{']))
	if '}' in datas_characters:
		print("\tNumber of '}}': {0}".format(all_characters_dict['}']))
	if '#' in datas_characters:
		print("\tNumber of '#': {0}".format(all_characters_dict['#']))
	if ';' in datas_characters:
		print("\tNumber of ';': {0}".format(all_characters_dict[';']))
		print("\t\tpercentage of ';' from total characters({1}): {0}".format(all_characters_dict[';']/float(len(file_data)), len(file_data)))
	if ';' in datas_characters and number_of_rows_in_data!=0:
		print("\tPercentage of ';' ending lines is: {0}".format(all_characters_dict[';']/float(number_of_rows_in_data)))
	"""
	return True #TODO:: change!


def start(file_name):

	try:
		f = open(file_name,"r")
		file_data = f.read()
		f.close()
		print("\nTesting file: "+file_name)
	except:
		print ("Couldn't read file, exiting...")
		sys.exit(1)

	if is_data_c_code(file_data):
		print ("File is probably C code!")
	else:
		print ("File probably ISN'T C code.")


def main(argv):
	"""
	if not len(argv) == 2:
		print 'Usage is: %s <file name>' % argv[0]
		sys.exit(1)

	file_name =""+ argv[1]
	start(file_name)
	"""

	for i in range(1,len(argv)):
		start(""+argv[i])

if __name__ == '__main__':
	main(sys.argv)

