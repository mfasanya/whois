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

      # The Blank parser isn't a real parser. It's just a fake parser
      # that acts as a parser but doesn't provide any special capability.
      #
      # It doesn't register itself in the parser_registry,
      # it doesn't scan any string, it only exists to be initialized
      # in case a record needs to create a parser for a WHOIS server
      # not yet supported.
      #
      class Blank < Base

        property_not_supported :status

        # The server is contacted only in case of a registered domain.
        property_supported :available? do
          false
        end

        property_supported :registered? do
          !available?
        end

        #property_supported :registrar do
        #  Record::Registrar.new(
        #      name:         content_for_scanner[/Registrar: (.+)\n/, 1],
        #      url:          content_for_scanner[/Registrar URL: (.+)\n/, 1],
        #  )
        #end

        property_supported :registrant_contacts do
          if content_for_scanner =~ /Registrant/
            build_contact('Registrant', Record::Contact::TYPE_REGISTRANT)
          end
        end

        property_supported :admin_contacts do
          if content_for_scanner =~ /Admin/
            build_contact('Admin', Record::Contact::TYPE_ADMINISTRATIVE)
          end
        end

        property_supported :technical_contacts do
          if content_for_scanner =~ /Tech/
            build_contact('Tech', Record::Contact::TYPE_TECHNICAL)
          end
        end

        property_supported :nameservers do
          content_for_scanner.scan(/Name Server: (.+)\n/).map do |line|
            Record::Nameserver.new(name: line[0].strip)
          end
        end

      private

        def build_contact(element, type)
          Record::Contact.new(
              type:         type,
              id:           nil,
              name:         value_for_property(element, 'Name'),
              organization: value_for_property(element, 'Organization'),
              address:      value_for_property(element, 'Street'),
              city:         value_for_property(element, 'City'),
              zip:          value_for_property(element, 'Postal Code'),
              state:        value_for_property(element, 'State/Province'),
              country:      value_for_property(element, 'Country'),
              phone:        value_for_property(element, 'Phone'),
              fax:          value_for_property(element, 'Fax'),
              email:        value_for_property(element, 'Email')
          )
        end

        def value_for_property(element, property)
          matches = content_for_scanner.scan(/#{element} #{property}:\s(.+)\n/)
          value = matches.collect(&:first).join(', ')
          if value == ""
            nil
          else
            value.force_encoding('UTF-8')
          end
        end

        #Whois::Record::Parser::PROPERTIES.each do |method|
        #  define_method(method) do
        #    raise ParserNotFound, "Unable to find a parser for the server `#{part.host}'"
        #  end
        #end

      end

    end
  end
end