#--
# Ruby Whois
#
# An intelligent pure Ruby WHOIS client and parser.
#
# Copyright (c) 2009-2014 Simone Carletti <weppos@weppos.net>
#++


require 'whois/record/parser/base'


module Whois
  class Record
    class Parser

      # = whois.nic.lv parser
      #
      # Parser for the whois.nic.lv server.
      #
      # NOTE: This parser is just a stub and provides only a few basic methods
      # to check for domain availability and get domain status.
      # Please consider to contribute implementing missing methods.
      # See WhoisNicIt parser for an explanation of all available methods
      # and examples.
      #
      class WhoisNicLv < Base

        property_supported :status do
          if available?
            :available
          else
            :registered
          end
        end

        property_supported :available? do
           !!(content_for_scanner =~ /Status: free/)
        end

        property_supported :registered? do
          !available?
        end


        property_not_supported :created_on

        property_supported :updated_on do
          if content_for_scanner =~ /Changed:\s+(.+)\n/
            # Hack to remove usec. Do you know a better way?
            # Time.utc(*Time.parse($1).to_a)
            Time.parse($1)
          end
        end

        property_not_supported :expires_on
        
        property_supported :registrant_contacts do
          if content_for_scanner =~ /\[Registrar\]\n((.+\n)+)\n/
            lines = $1.split("\n").map(&:strip)

            address = nil
            fax = nil
            phone = nil
            email = nil
            name = nil

            lines.each do |line|
              if content_for_scanner =~ /Name:\s(.+)+/
                name = $1
              elsif content_for_scanner =~ /Email:\s(.+)+/
                email = $1
              elsif content_for_scanner =~ /Fax:\s(.+)+/
                fax = $1
              elsif content_for_scanner =~ /Phone:\s(.+)+/
                phone = $1
              elsif content_for_scanner =~ /Address:\s(.+)+/
                address = $1
              end
            end

            Record::Contact.new(
              :type => Record::Contact::TYPE_REGISTRANT,
              :name => name,
              :address => address,
              :phone => phone,
              :email => email
            )
          end
        end


        property_supported :nameservers do
          content_for_scanner.scan(/Nserver:\s+(.+)\n/).flatten.map do |name|
            Record::Nameserver.new(:name => name)
          end
        end

      end

    end
  end
end
