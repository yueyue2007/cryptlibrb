#!/usr/bin/env ruby

# test how to use thor gem 

require 'thor'

class ThorExample < Thor

	desc "start","start server"	
	method_option :enviroment,:default =>"development",:alias=>"-e",
		:desc => "which environment you wnt server run.?"
	method_option :daemon,:type => :boolean, :default => false, :alias => "-d",
		:desc => "running on damenon mode?"
	def start
		puts "start : #{options.inspect}"
	end

	desc "stop","stop server"
	method_option :delay,:default => 0,:alias => "-w",
		:desc => "wait server finish its job"	
	def stop
		puts "stop"
	end
	
end

ThorExample.start