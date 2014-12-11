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

      #
      # = whois.ripe.net parser
      #
      # Parser for the whois.ripe.net server.
      #
      # NOTE: This parser is just a stub and provides only a few basic methods
      # to check for domain availability and get domain status.
      # Please consider to contribute implementing missing methods.
      # See WhoisNicIt parser for an explanation of all available methods
      # and examples.
      #
      class WhoisRipeNet < Base

        property_supported :status do
          if available?
            :available
          else
            :registered
          end
        end

        property_supported :available? do
          !!(content_for_scanner =~ /%ERROR:101: no entries found/)
        end

        property_supported :registered? do
          !available?
        end


        property_not_supported :created_on

        property_not_supported :updated_on

        property_not_supported :expires_on

        property_supported :registrant_contacts do
          select = content_for_scanner.scan(/\n\n((.|\n)*?)source:/)

          email = nil
          phone = nil
          fax = nil
          name = nil
          organization = nil
          name = nil
          address = nil
          country = nil
          country_code = nil
          city = nil

          if select[1]
            count = 0
            data = select[1][0]
            
            arr = data.scan(/address: (.+?)\n/)

            arr.flatten.map do |line|
              if arr.length == 2
                if count == 0
                  address = line.strip
                elsif count == 1
                  city = line.strip
                end
              elsif arr.length == 1
                if count == 0
                  address = lin.strip
                end
              elsif arr.length == 3
                if count == 0
                  name = line.strip
                elsif count == 1
                  address = line.strip
                elsif count == 2
                  country = line.strip
                end
              end
              count += 1
            end

            if data =~ /abuse-mailbox: (.+?)\n/
              email = $1.strip
            end

            if data =~ /e-mail: (.+?)\n/
              email = $1.strip
            end

            if data =~ /phone: (.+?)\n/
              phone = $1.strip
            end

            if data =~ /fax-no: (.+?)\n/
              fax = $1.strip
            end

            if data =~ /person: (.+?)\n/
              name = $1.strip
            end

            if data =~ /country: (.+?)\n/
              country_code = $1.strip
            end

            if content_for_scanner =~ /descr: (.+?)\n/
              organization = $1.strip
            end

            Record::Contact.new(
              type:         Record::Contact::TYPE_REGISTRANT,
              id:           nil,
              organization: organization,
              name:         name,
              address:      address,
              country:      country,
              country_code: country_code,
              email:        email,
              phone:        phone,
              city:         city,
              fax:          fax, 
            )
          end
        end

        property_supported :technical_contacts do
          select = content_for_scanner.scan(/\n\n((.|\n)*?)source:/)

          email = nil
          phone = nil
          fax = nil
          name = nil
          organization = nil
          name = nil
          address = nil
          country = nil
          country_code = nil
          city = nil

          if select[2]
            count = 0
            data = select[2][0]

            arr = data.scan(/address: (.+?)\n/)

            arr.flatten.map do |line|
              if arr.length == 2
                if count == 0
                  address = line.strip
                elsif count == 1
                  city = line.strip
                end
              elsif arr.length == 1
                if count == 0
                  address = lin.strip
                end
              elsif arr.length == 3
                if count == 0
                  name = line.strip
                elsif count == 1
                  address = line.strip
                elsif count == 2
                  country = line.strip
                end
              end
              count += 1
            end

            if data =~ /abuse-mailbox: (.+?)\n/
              email = $1.strip
            end

            if data =~ /e-mail: (.+?)\n/
              email = $1.strip
            end

            if data =~ /phone: (.+?)\n/
              phone = $1.strip
            end

            if data =~ /fax-no: (.+?)\n/
              fax = $1.strip
            end

            if data =~ /person: (.+?)\n/
              name = $1.strip
            end

            if data =~ /country: (.+?)\n/
              country_code = $1.strip
            end

            if content_for_scanner =~ /descr: (.+?)\n/
              organization = $1.strip
            end

            Record::Contact.new(
              type:         Record::Contact::TYPE_TECHNICAL,
              id:           nil,
              organization: organization,
              name:         name,
              address:      address,
              country:      country,
              country_code: country_code,
              email:        email,
              phone:        phone,
              city:         city,
              fax:          fax, 
            )
          end
        end

        property_supported :registrar do
          Record::Registrar.new(
              organization:  content_for_scanner[/netname: (.+)\n/, 1].strip,
              name:          content_for_scanner[/descr: (.+)\n/, 1].strip,
          )
        end


        # Nameservers are listed in the following formats:
        #
        #   nserver:      ns.nic.mc
        #   nserver:      ns.nic.mc 195.78.6.131
        #
        property_supported :nameservers do
          content_for_scanner.scan(/nserver:\s+(.+)\n/).flatten.map do |line|
            name, ipv4 = line.split(/\s+/)
            Record::Nameserver.new(:name => name.downcase, :ipv4 => ipv4)
          end
        end

        def response_throttled?
          !content_for_scanner.match(/Query rate limit exceeded/).nil?
        end

      end

    end
  end
end
