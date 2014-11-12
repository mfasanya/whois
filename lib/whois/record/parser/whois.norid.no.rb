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

      # Parser for the whois.norid.no server.
      #
      # @note This parser is just a stub and provides only a few basic methods
      #   to check for domain availability and get domain status.
      #   Please consider to contribute implementing missing methods.
      #
      # @see Whois::Record::Parser::Example
      #   The Example parser for the list of all available methods.
      #
      class WhoisNoridNo < Base

        property_supported :status do
          if available?
            :available
          else
            :registered
          end
        end

        property_supported :available? do
          !!(content_for_scanner =~ /^% No match/)
        end

        property_supported :registered? do
          !available?
        end

        property_supported :registrant_contacts do
          build_contact(Record::Contact::TYPE_REGISTRANT)
        end

        property_supported :created_on do
          if content_for_scanner =~ /Created:\s+(.*)\n/
            Time.parse($1)
          end
        end

        property_supported :updated_on do
          if content_for_scanner =~ /Last updated:\s+(.*)\n/
            Time.parse($1)
          end
        end

        property_not_supported :expires_on

        private

        def build_contact(type)
          Record::Contact.new(
              type:         type,
              id:           nil,
              name:         value_for_property('Name.......................'),
              address:      value_for_property('Post Address...............'),
              city:         value_for_property('Postal Area................'),
              zip:          value_for_property('Postal Code................'),
              country_code: value_for_property('Country....................'),
              phone:        value_for_property('Phone Number...............'),
              email:        value_for_property('Email Address..............')
          )
        end

        def value_for_property(property)
          matches = content_for_scanner.scan(/#{property}:\s(.+)\n/)
          value = matches.collect(&:first).join(', ')
          if value == ""
            nil
          else
            value
          end
        end

      end

    end
  end
end
