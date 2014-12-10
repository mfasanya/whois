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

      # Parser for the whois.godaddy.com server.
      #
      # @see Whois::Record::Parser::Example
      #   The Example parser for the list of all available methods.
      #
      class WhoisArinNet < Base

        property_not_supported :status

        # The server is contacted only in case of a registered domain.
        property_supported :available? do
          !!(content_for_scanner =~ /No match found for/)
        end

        property_supported :registered? do
          !available?
        end

        property_supported :created_on do
          if content_for_scanner =~ /RegDate: (.+?)\n/
            Time.parse($1)
          end
        end

        property_supported :updated_on do
          if content_for_scanner =~ /Updated: (.+?)\n/
            Time.parse($1)
          end
        end

        #property_supported :registrar do
        #  Record::Registrar.new(
        #      name:         content_for_scanner[/Registrar: (.+)\n/, 1],
        #      url:          content_for_scanner[/Registrar URL: (.+)\n/, 1],
        #  )
        #end

        property_supported :registrant_contacts do
            Record::Contact.new(
              type:         Record::Contact::TYPE_REGISTRANT,
              id:           value_for_property('OrgId'),
              name:         nil,
              organization: value_for_property('OrgName'),
              address:      value_for_property('Address'),
              city:         value_for_property('City'),
              zip:          value_for_property('PostalCode'),
              state:        value_for_property('StateProv'),
              country_code: value_for_property('Country')
            )
        end

        property_supported :admin_contacts do
          Record::Contact.new(
              type:         Record::Contact::TYPE_ADMINISTRATIVE,
              name:         value_for_property('OrgTechName'),
              phone:        value_for_property('OrgTechPhone'),
              email:        value_for_property('OrgTechEmail'), 
          )
        end

        property_supported :technical_contacts do
           Record::Contact.new(
              type:         Record::Contact::TYPE_TECHNICAL,
              name:         value_for_property('OrgAbuseName'),
              phone:        value_for_property('OrgAbusePhone'),
              email:        value_for_property('OrgAbuseEmail'), 
            )
        end

      private

        def value_for_property(property)
          matches = content_for_scanner.scan(/#{property}: (.+?)\n/)
          value = matches.collect(&:first).join(', ')
          if value == ""
            nil
          else
            value.strip
          end
        end

      end

    end
  end
end
