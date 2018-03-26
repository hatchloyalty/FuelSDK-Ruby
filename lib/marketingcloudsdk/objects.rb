# frozen_string_literal: true

# Copyright (c) 2013 ExactTarget, Inc.
#
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without modification, are permitted provided that the
#
# following conditions are met:
#
# 1. Redistributions of source code must retain the above copyright notice, this list of conditions and the
#
# following disclaimer.
#
# 2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the
#
# following disclaimer in the documentation and/or other materials provided with the distribution.
#
# 3. Neither the name of the copyright holder nor the names of its contributors may be used to endorse or promote
#
# products derived from this software without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES,
#
# INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
#
# DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
#
# SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
#
# SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
#
# WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE
#
# USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

module MarketingCloudSDK
  module Objects
    module Soap
      module Read
        attr_accessor :filter
        def get(_id = nil)
          client.soap_get _id || id, properties, filter
        end

        def info
          client.soap_describe id
        end
      end

      module CUD # create, update, delete
        def post
          if respond_to?('folder_property') && !folder_id.nil?
            properties[folder_property] = folder_id
          elsif respond_to?('folder_property') && !folder_property.nil? && !client.package_name.nil?
            if client.package_folders.nil?
              getPackageFolder = ET_Folder.new
              getPackageFolder.authStub = client
              getPackageFolder.properties = %w[ID ContentType]
              getPackageFolder.filter = { 'Property' => 'Name', 'SimpleOperator' => 'equals', 'Value' => client.package_name }
              resultPackageFolder = getPackageFolder.get
              if resultPackageFolder.status
                client.package_folders = {}
                resultPackageFolder.results.each do |value|
                  client.package_folders[value[:content_type]] = value[:id]
                end
              else
                raise "Unable to retrieve folders from account due to: #{resultPackageFolder.message}"
              end
            end

            unless client.package_folders.key?(folder_media_type)
              if client.parentFolders.nil?
                parentFolders = ET_Folder.new
                parentFolders.authStub = client
                parentFolders.properties = %w[ID ContentType]
                parentFolders.filter = { 'Property' => 'ParentFolder.ID', 'SimpleOperator' => 'equals', 'Value' => '0' }
                resultParentFolders = parentFolders.get
                if resultParentFolders.status
                  client.parent_folders = {}
                  resultParentFolders.results.each do |value|
                    client.parent_folders[value[:content_type]] = value[:id]
                  end
                else
                  raise "Unable to retrieve folders from account due to: #{resultParentFolders.message}"
                end
              end

              newFolder = ET_Folder.new
              newFolder.authStub = client
              newFolder.properties = { 'Name' => client.package_name, 'Description' => client.package_name, 'ContentType' => folder_media_type, 'IsEditable' => 'true', 'ParentFolder' => { 'ID' => client.parentFolders[folder_media_type] } }
              folderResult = newFolder.post
              if folderResult.status
                client.package_folders[folder_media_type] = folderResult.results[0][:new_id]
              else
                raise "Unable to create folder for Post due to: #{folderResult.message}"
              end

            end
            properties[folder_property] = client.package_folders[folder_media_type]
          end
          client.soap_post id, properties
        end

        def patch
          client.soap_patch id, properties
        end

        def delete
          client.soap_delete id, properties
        end
      end

      module Upsert
        def put
          client.soap_put id, properties
        end
      end
    end

    module Rest
      module Read
        def get
          client.rest_get id, properties
        end
      end

      module CUD
        def post
          client.rest_post id, properties
        end

        def patch
          client.rest_patch id, properties
        end

        def delete
          client.rest_delete id, properties
        end
      end
    end

    class Base
      attr_accessor :properties, :client
      attr_reader :id

      alias props= properties= # backward compatibility
      alias authStub= client= # backward compatibility

      attr_reader :properties

      # Backwards compatibility
      def props
        @properties
      end

      def id
        self.class.id
      end

      class << self
        def id
          name.split('::').pop
        end
      end
    end
  end

  class BounceEvent < Objects::Base
    attr_accessor :get_since_last_batch
    include Objects::Soap::Read
  end

  class ClickEvent < Objects::Base
    attr_accessor :get_since_last_batch
    include Objects::Soap::Read
  end

  class ContentArea < Objects::Base
    include Objects::Soap::Read
    include Objects::Soap::CUD
    attr_accessor :folder_id

    def folder_property
      'CategoryID'
    end

    def folder_media_type
      'content'
    end
  end

  class DataFolder < Objects::Base
    include Objects::Soap::Read
    include Objects::Soap::CUD
  end

  class Folder < DataFolder
    class << self
      def id
        DataFolder.id
      end
    end
  end

  class Email < Objects::Base
    include Objects::Soap::Read
    include Objects::Soap::CUD
    attr_accessor :folder_id

    def folder_property
      'CategoryID'
    end

    def folder_media_type
      'email'
    end

    class SendDefinition < Objects::Base
      include Objects::Soap::Read
      include Objects::Soap::CUD
      attr_accessor :folder_id

      def id
        'EmailSendDefinition'
      end

      def folder_property
        'CategoryID'
      end

      def folder_media_type
        'userinitiatedsends'
      end

      def send
        perform_response = client.soap_perform id, 'start', properties
        if perform_response.status
          @last_task_id = perform_response.results[0][:result][:task][:id]
        end
        perform_response
      end

      def status
        client.soap_get 'Send', ['ID', 'CreatedDate', 'ModifiedDate', 'Client.ID', 'Email.ID', 'SendDate', 'FromAddress', 'FromName', 'Duplicates', 'InvalidAddresses', 'ExistingUndeliverables', 'ExistingUnsubscribes', 'HardBounces', 'SoftBounces', 'OtherBounces', 'ForwardedEmails', 'UniqueClicks', 'UniqueOpens', 'NumberSent', 'NumberDelivered', 'NumberTargeted', 'NumberErrored', 'NumberExcluded', 'Unsubscribes', 'MissingAddresses', 'Subject', 'PreviewURL', 'SentDate', 'EmailName', 'Status', 'IsMultipart', 'SendLimit', 'SendWindowOpen', 'SendWindowClose', 'BCCEmail', 'EmailSendDefinition.ObjectID', 'EmailSendDefinition.CustomerKey'], 'Property' => 'ID', 'SimpleOperator' => 'equals', 'Value' => @last_task_id
      end

      private

      attr_accessor :last_task_id
    end
  end

  class Import < Objects::Base
    include Objects::Soap::Read
    include Objects::Soap::CUD

    def id
      'ImportDefinition'
    end

    def post
      originalProp = properties
      cleanProps
      obj = super
      properties = originalProp
      obj
    end

    def patch
      originalProp = properties
      cleanProps
      obj = super
      properties = originalProp
      obj
    end

    def start
      perform_response = client.soap_perform id, 'start', properties
      if perform_response.status
        @last_task_id = perform_response.results[0][:result][:task][:id]
      end
      perform_response
    end

    def status
      client.soap_get 'ImportResultsSummary', %w[ImportDefinitionCustomerKey TaskResultID ImportStatus StartDate EndDate DestinationID NumberSuccessful NumberDuplicated NumberErrors TotalRows ImportType], 'Property' => 'TaskResultID', 'SimpleOperator' => 'equals', 'Value' => @last_task_id
    end

    private

    attr_accessor :last_task_id

    def cleanProps
      # If the ID property is specified for the destination then it must be a list import
      if properties.key?('DestinationObject')
        if properties['DestinationObject'].key?('ID')
          properties[:attributes!] = { 'DestinationObject' => { 'xsi:type' => 'tns:List' } }
        end
      end
    end
  end

  class List < Objects::Base
    include Objects::Soap::Read
    include Objects::Soap::CUD
    attr_accessor :folder_id

    def folder_property
      'Category'
    end

    def folder_media_type
      'list'
    end

    class Subscriber < Objects::Base
      include Objects::Soap::Read
      def id
        'ListSubscriber'
      end
    end
  end

  class OpenEvent < Objects::Base
    attr_accessor :get_since_last_batch
    include Objects::Soap::Read
  end

  class SentEvent < Objects::Base
    attr_accessor :get_since_last_batch
    include Objects::Soap::Read
  end

  class Subscriber < Objects::Base
    include Objects::Soap::Read
    include Objects::Soap::CUD
    include Objects::Soap::Upsert
  end

  class UnsubEvent < Objects::Base
    attr_accessor :get_since_last_batch
    include Objects::Soap::Read
  end

  class ProfileAttribute < Objects::Base
    def get
      client.soap_describe 'Subscriber'
    end

    def post
      client.soap_configure 'PropertyDefinition', 'create', properties
    end

    def delete
      client.soap_configure 'PropertyDefinition', 'delete', properties
    end

    def patch
      client.soap_configure 'PropertyDefinition', 'update', properties
    end
  end

  class TriggeredSend < Objects::Base
    include Objects::Soap::Read
    include Objects::Soap::CUD
    attr_accessor :folder_id, :subscribers, :attributes
    def id
      'TriggeredSendDefinition'
    end

    def folder_property
      'CategoryID'
    end

    def folder_media_type
      'triggered_send'
    end

    def send
      if properties.is_a? Array
        tscall = []
        properties.each do |p|
          tscall.push('TriggeredSendDefinition' => { 'CustomerKey' => p['CustomerKey'] }, 'Subscribers' => p['Subscribers'], 'Attributes' => p['Attributes'])
        end
      else
        tscall = { 'TriggeredSendDefinition' => properties, 'Subscribers' => @subscribers, 'Attributes' => @attributes }
      end
      client.soap_post 'TriggeredSend', tscall
    end
  end

  class DataExtension < Objects::Base
    include Objects::Soap::Read
    include Objects::Soap::CUD
    attr_accessor :fields, :folder_id

    def folder_property
      'CategoryID'
    end

    def folder_media_type
      'dataextension'
    end

    alias columns= fields= # backward compatibility

    def post
      munge_fields properties
      super
    end

    def patch
      munge_fields properties
      super
    end

    class Column < Objects::Base
      include Objects::Soap::Read
      def id
        'DataExtensionField'
      end

      def get
        if filter&.is_a?(Hash) && \
           filter.include?('Property') && (filter['Property'] == 'CustomerKey')
          filter['Property'] = 'DataExtension.CustomerKey'
        end
        super
      end
    end

    class Row < Objects::Base
      include Objects::Soap::Read
      include Objects::Soap::CUD
      include Objects::Soap::Upsert

      attr_accessor :name, :customer_key

      # backward compatibility
      alias Name= name=
      alias CustomerKey= customer_key=

      def id
        'DataExtensionObject'
      end

      def get
        super "#{id}[#{name}]"
      end

      def name
        retrieve_required unless @name
        @name
      end

      def customer_key
        retrieve_required unless @customer_key
        @customer_key
      end

      def post
        munge_properties properties
        super
      end

      def patch
        munge_properties properties
        super
      end

      def put
        munge_properties properties
        super
      end

      def delete
        munge_keys properties
        super
      end

      private

      #::TODO::
      # opportunity for meta programming here... but need to get this out the door
      def munge_keys(d)
        if d.is_a? Array
          d.each do |o|
            next if explicit_keys(o) && explicit_customer_key(o)

            formatted = []
            o['CustomerKey'] = customer_key unless explicit_customer_key o
            next if explicit_properties(o)
            o.each do |k, v|
              next if k == 'CustomerKey'
              formatted.concat MarketingCloudSDK.format_name_value_pairs k => v
              o.delete k
            end
            o['Keys'] = { 'Key' => formatted }
          end
        else
          formatted = []
          d.each do |k, v|
            next if k == 'CustomerKey'
            formatted.concat MarketingCloudSDK.format_name_value_pairs k => v
            d.delete k
          end
          d['CustomerKey'] = customer_key
          d['Keys'] = { 'Key' => formatted }
        end
      end

      def explicit_keys(h)
        h['Keys'] && h['Keys']['Key']
      end

      def munge_properties(d)
        if d.is_a? Array
          d.each do |o|
            next if explicit_properties(o) && explicit_customer_key(o)

            formatted = []
            o['CustomerKey'] = customer_key unless explicit_customer_key o
            next if explicit_properties(o)
            o.each do |k, v|
              next if k == 'CustomerKey'
              formatted.concat MarketingCloudSDK.format_name_value_pairs k => v
              o.delete k
            end
            o['Properties'] = { 'Property' => formatted }
          end
        else
          formatted = []
          d.each do |k, v|
            formatted.concat MarketingCloudSDK.format_name_value_pairs k => v
            d.delete k
          end
          d['CustomerKey'] = customer_key
          d['Properties'] = { 'Property' => formatted }
        end
      end

      def explicit_properties(h)
        h['Properties'] && h['Properties']['Property']
      end

      def explicit_customer_key(h)
        h['CustomerKey']
      end

      def retrieve_required
        # have to use instance variables so we don't recursivelly retrieve_required
        if !@name && !@customer_key
          raise 'Unable to process DataExtension::Row ' \
              'request due to missing CustomerKey and Name'
        end
        if !@name || !@customer_key
          filter = {
            'Property' => @name.nil? ? 'CustomerKey' : 'Name',
            'SimpleOperator' => 'equals',
            'Value' => @customer_key || @name
          }
          rsp = client.soap_get 'DataExtension', %w[Name CustomerKey], filter
          if rsp.success? && rsp.results.count == 1
            self.name = rsp.results.first[:name]
            self.customer_key = rsp.results.first[:customer_key]
          else
            raise 'Unable to process DataExtension::Row'
          end
        end
      end
    end

    private

    def munge_fields(d)
      # maybe one day will make it smart enough to zip properties and fields if count is same?
      if d.is_a?(Array) && (d.count > 1) && (fields && !fields.empty?)
        # we could map the field to all DataExtensions, but lets make user be explicit.
        # if they are going to use fields attribute properties should
        # be a single DataExtension Defined in a Hash
        raise 'Unable to handle muliple DataExtension definitions and a field definition'
      end

      if d.is_a? Array
        d.each do |de|
          if (explicit_fields(de) && (de['columns'] || de['fields'] || has_fields)) ||
             (de['columns'] && (de['fields'] || has_fields)) ||
             (de['fields'] && has_fields)
            raise 'Fields are defined in too many ways. Please only define once.' # ahhh what, to do...
          end

          # let users who chose, to define fields explicitly within the hash definition
          next if explicit_fields de

          de['Fields'] = { 'Field' => de['columns'] || de['fields'] || fields }
          # sanitize

          raise 'DataExtension needs atleast one field.' unless de['Fields']['Field']
        end
      else
        properties['Fields'] = { 'Field' => properties['columns'] || properties['fields'] || fields }
        raise 'DataExtension needs atleast one field.' unless properties['Fields']['Field']
        properties.delete 'columns'
        properties.delete 'fields'
      end
    end

    def explicit_fields(h)
      h['Fields'] && h['Fields']['Field']
    end

    def has_fields
      fields && !fields.empty?
    end
  end

  class Campaign < Objects::Base
    include Objects::Rest::Read
    include Objects::Rest::CUD

    def properties
      @properties ||= {}
      @properties['id'] = '' unless @properties.include? 'id'
      @properties
    end

    def id
      'https://www.exacttargetapis.com/hub/v1/campaigns/%{id}'
    end

    class Asset < Objects::Base
      include Objects::Rest::Read
      include Objects::Rest::CUD

      def properties
        @properties ||= {}
        @properties['assetId'] = '' unless @properties.include? 'assetId'
        @properties
      end

      def id
        'https://www.exacttargetapis.com/hub/v1/campaigns/%{id}/assets/%{assetId}'
      end
    end
  end

  # Direct Verb Access Section

  class Get < Objects::Base
    include Objects::Soap::Read
    attr_accessor :id

    def initialize(client, id, properties, filter)
      self.properties = properties
      self.filter = filter
      self.client = client
      self.id = id
    end

    def get
      super id
    end

    class << self
      def new(client, id, properties = nil, filter = nil)
        o = allocate
        o.send :initialize, client, id, properties, filter
        o.get
      end
    end
  end

  class Post < Objects::Base
    include Objects::Soap::CUD
    attr_accessor :id

    def initialize(client, id, properties)
      self.properties = properties
      self.client = client
      self.id = id
    end

    def post
      super
    end

    class << self
      def new(client, id, properties = nil)
        o = allocate
        o.send :initialize, client, id, properties
        o.post
      end
    end
  end

  class Delete < Objects::Base
    include Objects::Soap::CUD
    attr_accessor :id

    def initialize(client, id, properties)
      self.properties = properties
      self.client = client
      self.id = id
    end

    def delete
      super
    end

    class << self
      def new(client, id, properties = nil)
        o = allocate
        o.send :initialize, client, id, properties
        o.delete
      end
    end
  end

  class Patch < Objects::Base
    include Objects::Soap::CUD
    attr_accessor :id

    def initialize(client, id, properties)
      self.properties = properties
      self.client = client
      self.id = id
    end

    def patch
      super
    end

    class << self
      def new(client, id, properties = nil)
        o = allocate
        o.send :initialize, client, id, properties
        o.patch
      end
    end
  end
end
