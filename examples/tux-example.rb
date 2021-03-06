#!/usr/bin/env ruby

## Simple example of attaching to a process and letting it run

require 'ragweed'

pid = Ragweed::Debuggertux.find_by_regex(/gcalctool/)

begin
	t = Ragweed::Debuggertux.threads(pid)
	puts "Available pid/tdpids\n"
	t.each do |h| puts h end
	puts "Which thread do you want to attach to?"
	pid = STDIN.gets.chomp.to_i

    opts = {}
    opts[:fork] = true  ## This flag tells ragweed to trace any forked child processes
	d = Ragweed::Debuggertux.new(pid, opts)
	d.attach
	d.continue
	catch(:throw) { d.loop }
rescue
	puts "Maybe your PID is wrong?"
end
