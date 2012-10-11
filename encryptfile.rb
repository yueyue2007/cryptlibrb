#!/usr/bin/env ruby

###############################################
#
#   encrypt/decrypt a file 
#
##############################################

require 'optparse'

options = {}
options[:daemon] = false
options[:environment] = 'ubuntu' 
option_parser = OptionParser.new do |opts|
	opts.banner = 'displaying how to use the command line tool!'
	opts.separator ""
	opts.separator "commands"
	opts.separator "    start: start server"
	opts.separator "    stop stop server"
	opts.separator "    restart   restart server"
	opts.separator ""
	opts.separator "options"

	opts.on("-e","--environment ENVIROMENT","which environment you want server run ") do |environment|
		options[:environment] = environment
	end

	opts.on("-d", "--daemon","running on daemon mode?") do 
		options[:daemon] = true
	end

	opts.on("-h","--help","help") do 
		puts option_parser
	end
end

option_parser.parse!

# case ARGV[0]
# when "start"
# 	puts "call start on options: #{options.inspect}"
# when "stop"
# 	puts "call stop on options: #{options.inspect}"
# when "restart"
# 	puts "call restart on options #{options.inspect}"
# else
# 	puts option_parser
# end

puts "we willl encrypt file:#{ARGV[0]},the options are #{options.inspect}"
