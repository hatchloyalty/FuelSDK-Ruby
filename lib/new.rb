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

require 'marketingcloudsdk/version'

require 'rubygems'
require 'open-uri'
require 'savon'
require 'date'
require 'json'
require 'yaml'
require 'jwt'

def indifferent_access(key, hash)
  hash[key.to_sym] || hash[key.to_s]
end

module MarketingCloudSDK
  class Soap
    def client
      'soap'
    end
  end

  class Rest
    def client
      'rest'
    end
  end

  class Client
    attr_reader :id, :secret, :signature

    def initialize(params = {}, debug = false)
      @debug = debug
      @id = indifferent_access :clientid, params
      @secret = indifferent_access :clientsecret, params
      @signature = indifferent_access :appsignature, params
    end
  end

  class SoapClient < Client
    def initialize(_getWSDL = true, params = {}, debug = false)
      super params, debug
      @wsdl = params['defaultwsdl']
    end
  end

  class RestClient < Client
  end

  # parse response
  class ET_Constructor
    attr_accessor :status, :code, :message, :results, :request_id, :moreResults

    def initialize(response = nil, rest = false)
      @results = []
      if !response.nil? && !rest
        envelope = response.hash[:envelope]
        @@body = envelope[:body]

        if !response.soap_fault? || !response.http_error?
          @code = response.http.code
          @status = true
        elsif response.soap_fault?
          @code = response.http.code
          @message = @@body[:fault][:faultstring]
          @status = false
        elsif response.http_error?
          @code = response.http.code
          @status = false
        end
      elsif
        @code = response.code
        @status = true
        @status = false if @code != '200'

        begin
          @results = JSON.parse(response.body)
        rescue StandardError
          @message = response.body
        end

      end
    end
  end

  class ET_CreateWSDL
    def initialize(path)
      # Get the header info for the correct wsdl
      response = HTTPI.head(@wsdl)
      if response && ((response.code >= 200) && (response.code <= 400))
        header = response.headers
        # Check when the WSDL was last modified
        modifiedTime = Date.parse(header['last-modified'])
        p = path + '/ExactTargetWSDL.xml'
        # Check if a local file already exists
        if File.file?(p) && File.readable?(p) && !File.zero?(p)
          createdTime = File.new(p).mtime.to_date

          # Check if the locally created WSDL older than the production WSDL
          createIt = createdTime < modifiedTime
        else
          createIt = true
        end

        if createIt
          res = open(@wsdl).read
          File.open(p, 'w+') do |f|
            f.write(res)
          end
        end
        @status = response.code
      else
        @status = response.code
      end
    end
  end

  class ET_Client < ET_CreateWSDL
    attr_accessor :auth, :ready, :status, :debug, :authToken
    attr_reader :authTokenExpiration, :internalAuthToken, :wsdlLoc, :clientId,
                :clientSecret, :soapHeader, :authObj, :path, :appsignature, :stackID, :refreshKey

    def initialize(getWSDL = true, debug = false, params = nil)
      config = YAML.load_file('config.yaml')
      @clientId = config['clientid']
      @clientSecret = config['clientsecret']
      @appsignature = config['appsignature']
      @wsdl = config['defaultwsdl']
      @debug = debug

      begin
        @path = File.dirname(__FILE__)

        # make a new WSDL
        super(@path) if getWSDL

        if params&.key?('jwt')
          jwt = JWT.decode(params['jwt'], @appsignature, true)
          @authToken = jwt['request']['user']['oauthToken']
          @authTokenExpiration = Time.new + jwt['request']['user']['expiresIn']
          @internalAuthToken = jwt['request']['user']['internalOauthToken']
          @refreshKey = jwt['request']['user']['refreshToken']

          determineStack

          @authObj = { 'oAuth' => { 'oAuthToken' => @internalAuthToken } }
          @authObj[:attributes!] = { 'oAuth' => { 'xmlns' => 'http://exacttarget.com' } }

          myWSDL = File.read(@path + '/ExactTargetWSDL.xml')
          @auth = Savon.client(
            soap_header: @authObj,
            wsdl: myWSDL,
            endpoint: @endpoint,
            wsse_auth: ['*', '*'],
            raise_errors: false,
            log: @debug,
            open_timeout: 180,
            read_timeout: 180
          )
        else
          refreshToken
        end
      rescue StandardError
        raise
      end

      @ready = if !@auth.operations.empty? && ((@status >= 200) && (@status <= 400))
                 true
               else
                 false
               end
    end

    attr_writer :debug

    def refreshToken(force = nil)
      # If we don't already have a token or the token expires within 5 min(300 seconds), get one
      if (@authToken.nil? || Time.new + 300 > @authTokenExpiration) || force
        begin
          uri = URI.parse('https://auth.exacttargetapis.com/v1/requestToken?legacy=1')
          http = Net::HTTP.new(uri.host, uri.port)
          http.use_ssl = true
          request = Net::HTTP::Post.new(uri.request_uri)
          jsonPayload = { 'clientId' => @clientId, 'clientSecret' => @clientSecret }

          # Pass in the refreshKey if we have it
          jsonPayload['refreshToken'] = @refreshKey if @refreshKey

          request.body = jsonPayload.to_json
          request.add_field 'Content-Type', 'application/json'
          tokenResponse = JSON.parse(http.request(request).body)

          unless tokenResponse.key?('accessToken')
            raise 'Unable to validate App Keys(ClientID/ClientSecret) provided: ' + http.request(request).body
          end

          @authToken = tokenResponse['accessToken']
          @authTokenExpiration = Time.new + tokenResponse['expiresIn']
          @internalAuthToken = tokenResponse['legacyToken']
          if tokenResponse.key?('refreshToken')
            @refreshKey = tokenResponse['refreshToken']
          end

          determineStack if @endpoint.nil?

          @authObj = { 'oAuth' => { 'oAuthToken' => @internalAuthToken } }
          @authObj[:attributes!] = { 'oAuth' => { 'xmlns' => 'http://exacttarget.com' } }

          myWSDL = File.read(@path + '/ExactTargetWSDL.xml')
          @auth = Savon.client(
            soap_header: @authObj,
            wsdl: myWSDL,
            endpoint: @endpoint,
            wsse_auth: ['*', '*'],
            raise_errors: false,
            log: @debug
          )
        rescue Exception => e
          raise 'Unable to validate App Keys(ClientID/ClientSecret) provided: ' + e.message
        end
      end
    end

    def AddSubscriberToList(emailAddress, listIDs, subscriberKey = nil)
      newSub = ET_Subscriber.new
      newSub.authStub = self
      lists = []

      listIDs.each do |p|
        lists.push('ID' => p)
      end

      newSub.props = { 'EmailAddress' => emailAddress, 'Lists' => lists }
      newSub.props['SubscriberKey'] = subscriberKey unless subscriberKey.nil?

      # Try to add the subscriber
      postResponse = newSub.post

      if postResponse.status == false
        # If the subscriber already exists in the account then we need to do an update.
        # Update Subscriber On List
        if postResponse.results[0][:error_code] == '12014'
          patchResponse = newSub.patch
          return patchResponse
        end
      end
      postResponse
    end

    def CreateDataExtensions(dataExtensionDefinitions)
      newDEs = ET_DataExtension.new
      newDEs.authStub = self

      newDEs.props = dataExtensionDefinitions
      postResponse = newDEs.post

      postResponse
    end

    protected

    def determineStack
      uri = URI.parse('https://www.exacttargetapis.com/platform/v1/endpoints/soap?access_token=' + @authToken)
      http = Net::HTTP.new(uri.host, uri.port)

      http.use_ssl = true

      request = Net::HTTP::Get.new(uri.request_uri)

      contextResponse = JSON.parse(http.request(request).body)
      @endpoint = contextResponse['url']
    rescue StandardError => e
      raise 'Unable to determine stack using /platform/v1/tokenContext: ' + e.message
    end
  end

  class ET_Describe < ET_Constructor
    def initialize(authStub = nil, objType = nil)
      authStub.refreshToken
      response = authStub.auth.call(:describe, message: {
                                      'DescribeRequests' =>
                                        { 'ObjectDefinitionRequest' =>
                                          { 'ObjectType' => objType } }
                                    })
    ensure
      super(response)

      if @status
        objDef = @@body[:definition_response_msg][:object_definition]

        @overallStatus = if objDef
                           true
                         else
                           false
                         end
        @results = @@body[:definition_response_msg][:object_definition][:properties]
      end
    end
  end

  class ET_Post < ET_Constructor
    def initialize(authStub, objType, props = nil)
      @results = []

      begin
        authStub.refreshToken
        if props.is_a? Array
          obj = {
            'Objects' => [],
            :attributes! => { 'Objects' => { 'xsi:type' => ('tns:' + objType) } }
          }
          props.each do |p|
            obj['Objects'] << p
          end
        else
          obj = {
            'Objects' => props,
            :attributes! => { 'Objects' => { 'xsi:type' => ('tns:' + objType) } }
          }
        end

        response = authStub.auth.call(:create, message: obj)
      ensure
        super(response)
        if @status
          @status = false if @@body[:create_response][:overall_status] != 'OK'
          # @results = @@body[:create_response][:results]
          unless @@body[:create_response][:results].nil?
            if !@@body[:create_response][:results].is_a? Hash
              @results += @@body[:create_response][:results]
            else
              @results.push(@@body[:create_response][:results])
            end
          end
        end
      end
    end
  end

  class ET_Delete < ET_Constructor
    def initialize(authStub, objType, props = nil)
      @results = []
      begin
        authStub.refreshToken
        if props.is_a? Array
          obj = {
            'Objects' => [],
            :attributes! => { 'Objects' => { 'xsi:type' => ('tns:' + objType) } }
          }
          props.each do |p|
            obj['Objects'] << p
          end
        else
          obj = {
            'Objects' => props,
            :attributes! => { 'Objects' => { 'xsi:type' => ('tns:' + objType) } }
          }
        end

        response = authStub.auth.call(:delete, message: obj)
      ensure
        super(response)
        if @status
          @status = false if @@body[:delete_response][:overall_status] != 'OK'
          if !@@body[:delete_response][:results].is_a? Hash
            @results += @@body[:delete_response][:results]
          else
            @results.push(@@body[:delete_response][:results])
          end
        end
      end
    end
  end

  class ET_Patch < ET_Constructor
    def initialize(authStub, objType, props = nil)
      @results = []
      begin
        authStub.refreshToken
        if props.is_a? Array
          obj = {
            'Objects' => [],
            :attributes! => { 'Objects' => { 'xsi:type' => ('tns:' + objType) } }
          }
          props.each do |p|
            obj['Objects'] << p
          end
        else
          obj = {
            'Objects' => props,
            :attributes! => { 'Objects' => { 'xsi:type' => ('tns:' + objType) } }
          }
        end

        response = authStub.auth.call(:update, message: obj)
      ensure
        super(response)
        if @status
          @status = false if @@body[:update_response][:overall_status] != 'OK'
          if !@@body[:update_response][:results].is_a? Hash
            @results += @@body[:update_response][:results]
          else
            @results.push(@@body[:update_response][:results])
          end
        end
      end
    end
  end

  class ET_Continue < ET_Constructor
    def initialize(authStub, request_id)
      @results = []
      authStub.refreshToken
      obj = { 'ContinueRequest' => request_id }
      response = authStub.auth.call(:retrieve, message: { 'RetrieveRequest' => obj })

      super(response)

      if @status
        if @@body[:retrieve_response_msg][:overall_status] != 'OK' && @@body[:retrieve_response_msg][:overall_status] != 'MoreDataAvailable'
          @status = false
          @message = @@body[:retrieve_response_msg][:overall_status]
        end

        @moreResults = false
        if @@body[:retrieve_response_msg][:overall_status] == 'MoreDataAvailable'
          @moreResults = true
        end

        if (!@@body[:retrieve_response_msg][:results].is_a? Hash) && !@@body[:retrieve_response_msg][:results].nil?
          @results += @@body[:retrieve_response_msg][:results]
        elsif !@@body[:retrieve_response_msg][:results].nil?
          @results.push(@@body[:retrieve_response_msg][:results])
        end

        # Store the Last Request ID for use with continue
        @request_id = @@body[:retrieve_response_msg][:request_id]
      end
    end
  end

  class ET_Get < ET_Constructor
    def initialize(authStub, objType, props = nil, filter = nil)
      @results = []
      authStub.refreshToken
      unless props
        resp = ET_Describe.new(authStub, objType)
        if resp
          props = []
          resp.results.map do |p|
            props << p[:name] if p[:is_retrievable]
          end
        end
      end

      # If the properties is a hash, then we just want to use the keys
      obj = if props.is_a? Hash
              { 'ObjectType' => objType, 'Properties' => props.keys }
            else
              { 'ObjectType' => objType, 'Properties' => props }
            end

      if filter
        if filter.key?('LogicalOperator')
          obj['Filter'] = filter
          obj[:attributes!] = { 'Filter' => { 'xsi:type' => 'tns:ComplexFilterPart' } }
          obj['Filter'][:attributes!] = { 'LeftOperand' => { 'xsi:type' => 'tns:SimpleFilterPart' }, 'RightOperand' => { 'xsi:type' => 'tns:SimpleFilterPart' } }
        else
          obj['Filter'] = filter
          obj[:attributes!] = { 'Filter' => { 'xsi:type' => 'tns:SimpleFilterPart' } }
        end
      end

      response = authStub.auth.call(:retrieve, message: {
                                      'RetrieveRequest' => obj
                                    })

      super(response)

      if @status
        if @@body[:retrieve_response_msg][:overall_status] != 'OK' && @@body[:retrieve_response_msg][:overall_status] != 'MoreDataAvailable'
          @status = false
          @message = @@body[:retrieve_response_msg][:overall_status]
        end

        @moreResults = false
        if @@body[:retrieve_response_msg][:overall_status] == 'MoreDataAvailable'
          @moreResults = true
        end

        if (!@@body[:retrieve_response_msg][:results].is_a? Hash) && !@@body[:retrieve_response_msg][:results].nil?
          @results += @@body[:retrieve_response_msg][:results]
        elsif !@@body[:retrieve_response_msg][:results].nil?
          @results.push(@@body[:retrieve_response_msg][:results])
        end

        # Store the Last Request ID for use with continue
        @request_id = @@body[:retrieve_response_msg][:request_id]
      end
    end
  end

  class ET_BaseObject
    attr_accessor :authStub, :props
    attr_reader :obj, :lastRequestID, :endpoint

    def initialize
      @authStub = nil
      @props = nil
      @filter = nil
      @lastRequestID = nil
      @endpoint = nil
    end
  end

  class ET_GetSupport < ET_BaseObject
    attr_accessor :filter

    def get(props = nil, filter = nil)
      @props = props if props&.is_a?(Array)

      @props = @props.keys if @props&.is_a?(Hash)

      @filter = filter if filter&.is_a?(Hash)
      obj = ET_Get.new(@authStub, @obj, @props, @filter)

      @lastRequestID = obj.request_id

      obj
    end

    def info
      ET_Describe.new(@authStub, @obj)
    end

    def getMoreResults
      ET_Continue.new(@authStub, @lastRequestID)
    end
  end

  class ET_CUDSupport < ET_GetSupport
    def post
      @props = props if props&.is_a?(Hash)

      @extProps&.each do |key, value|
        @props[key.capitalize] = value
      end

      ET_Post.new(@authStub, @obj, @props)
    end

    def patch
      @props = props if props&.is_a?(Hash)

      ET_Patch.new(@authStub, @obj, @props)
    end

    def delete
      @props = props if props&.is_a?(Hash)

      ET_Delete.new(@authStub, @obj, @props)
    end
  end

  class ET_GetSupportRest < ET_BaseObject
    attr_reader :urlProps, :urlPropsRequired, :lastPageNumber

    def get(props = nil)
      @props = props if props&.is_a?(Hash)

      completeURL = @endpoint
      additionalQS = {}

      if @props&.is_a?(Hash)
        @props.each do |k, v|
          if @urlProps.include?(k)
            completeURL.sub!("{#{k}}", v)
          else
            additionalQS[k] = v
          end
        end
      end

      @urlPropsRequired.each do |value|
        if !@props || !@props.key?(value)
          raise "Unable to process request due to missing required prop: #{value}"
        end
      end

      @urlProps.each do |value|
        completeURL.sub!("/{#{value}}", '')
      end

      obj = ET_GetRest.new(@authStub, completeURL, additionalQS)

      if obj.results.key?('page')
        @lastPageNumber = obj.results['page']
        pageSize = obj.results['pageSize']
        if obj.results.key?('count')
          count = obj.results['count']
        elsif obj.results.key?('totalCount')
          count = obj.results['totalCount']
        end

        if !count.nil? && count > (@lastPageNumber * pageSize)
          obj.moreResults = true
        end
      end
      obj
    end

    def getMoreResults
      @props = props if props&.is_a?(Hash)

      originalPageValue = '1'
      removePageFromProps = false

      if !@props.nil? && @props.key?('$page')
        originalPageValue = @props['page']
      else
        removePageFromProps = true
      end

      @props = {} if @props.nil?

      @props['$page'] = @lastPageNumber + 1

      obj = get

      if removePageFromProps
        @props.delete('$page')
      else
        @props['$page'] = originalPageValue
      end

      obj
    end
  end

  class ET_CUDSupportRest < ET_GetSupportRest
    def post
      completeURL = @endpoint

      if @props&.is_a?(Hash)
        @props.each do |k, v|
          completeURL.sub!("{#{k}}", v) if @urlProps.include?(k)
        end
      end

      @urlPropsRequired.each do |value|
        if !@props || !@props.key?(value)
          raise "Unable to process request due to missing required prop: #{value}"
        end
      end

      # Clean Optional Parameters from Endpoint URL first
      @urlProps.each do |value|
        completeURL.sub!("/{#{value}}", '')
      end

      ET_PostRest.new(@authStub, completeURL, @props)
    end

    def patch
      completeURL = @endpoint
      # All URL Props are required when doing Patch
      @urlProps.each do |value|
        if !@props || !@props.key?(value)
          raise "Unable to process request due to missing required prop: #{value}"
        end
      end

      if @props&.is_a?(Hash)
        @props.each do |k, v|
          completeURL.sub!("{#{k}}", v) if @urlProps.include?(k)
        end
      end

      obj = ET_PatchRest.new(@authStub, completeURL, @props)
    end

    def delete
      completeURL = @endpoint
      # All URL Props are required when doing Patch
      @urlProps.each do |value|
        if !@props || !@props.key?(value)
          raise "Unable to process request due to missing required prop: #{value}"
        end
      end

      if @props&.is_a?(Hash)
        @props.each do |k, v|
          completeURL.sub!("{#{k}}", v) if @urlProps.include?(k)
        end
      end

      ET_DeleteRest.new(@authStub, completeURL)
    end
  end

  class ET_GetRest < ET_Constructor
    def initialize(authStub, endpoint, qs = nil)
      authStub.refreshToken

      if qs
        qs['access_token'] = authStub.authToken
      else
        qs = { 'access_token' => authStub.authToken }
      end

      uri = URI.parse(endpoint)
      uri.query = URI.encode_www_form(qs)
      http = Net::HTTP.new(uri.host, uri.port)
      http.use_ssl = true
      request = Net::HTTP::Get.new(uri.request_uri)
      requestResponse = http.request(request)

      @moreResults = false

      obj = super(requestResponse, true)
      obj
    end
  end

  class ET_ContinueRest < ET_Constructor
    def initialize(authStub, endpoint, qs = nil)
      authStub.refreshToken

      if qs
        qs['access_token'] = authStub.authToken
      else
        qs = { 'access_token' => authStub.authToken }
      end

      uri = URI.parse(endpoint)
      uri.query = URI.encode_www_form(qs)
      http = Net::HTTP.new(uri.host, uri.port)
      http.use_ssl = true
      request = Net::HTTP::Get.new(uri.request_uri)
      requestResponse = http.request(request)

      @moreResults = false

      super(requestResponse, true)
    end
  end

  class ET_PostRest < ET_Constructor
    def initialize(authStub, endpoint, payload)
      authStub.refreshToken

      qs = { 'access_token' => authStub.authToken }
      uri = URI.parse(endpoint)
      uri.query = URI.encode_www_form(qs)
      http = Net::HTTP.new(uri.host, uri.port)
      http.use_ssl = true
      request = Net::HTTP::Post.new(uri.request_uri)
      request.body = payload.to_json
      request.add_field 'Content-Type', 'application/json'
      requestResponse = http.request(request)

      super(requestResponse, true)
    end
  end

  class ET_PatchRest < ET_Constructor
    def initialize(authStub, endpoint, payload)
      authStub.refreshToken

      qs = { 'access_token' => authStub.authToken }
      uri = URI.parse(endpoint)
      uri.query = URI.encode_www_form(qs)
      http = Net::HTTP.new(uri.host, uri.port)
      http.use_ssl = true
      request = Net::HTTP::Patch.new(uri.request_uri)
      request.body = payload.to_json
      request.add_field 'Content-Type', 'application/json'
      requestResponse = http.request(request)
      super(requestResponse, true)
    end
  end

  class ET_DeleteRest < ET_Constructor
    def initialize(authStub, endpoint)
      authStub.refreshToken

      qs = { 'access_token' => authStub.authToken }

      uri = URI.parse(endpoint)
      uri.query = URI.encode_www_form(qs)
      http = Net::HTTP.new(uri.host, uri.port)
      http.use_ssl = true
      request = Net::HTTP::Delete.new(uri.request_uri)
      requestResponse = http.request(request)
      super(requestResponse, true)
    end
  end

  class ET_Campaign < ET_CUDSupportRest
    def initialize
      super
      @endpoint = 'https://www.exacttargetapis.com/hub/v1/campaigns/{id}'
      @urlProps = ['id']
      @urlPropsRequired = []
    end

    class Asset < ET_CUDSupportRest
      def initialize
        super
        @endpoint = 'https://www.exacttargetapis.com/hub/v1/campaigns/{id}/assets/{assetId}'
        @urlProps = %w[id assetId]
        @urlPropsRequired = ['id']
      end
    end
  end

  class ET_Subscriber < ET_CUDSupport
    def initialize
      super
      @obj = 'Subscriber'
    end
  end

  class ET_DataExtension < ET_CUDSupport
    attr_accessor :columns

    def initialize
      super
      @obj = 'DataExtension'
    end

    def post
      originalProps = @props

      if @props.is_a? Array
        multiDE = []
        @props.each do |currentDE|
          currentDE['Fields'] = {}
          currentDE['Fields']['Field'] = []
          currentDE['columns'].each do |key|
            currentDE['Fields']['Field'].push(key)
          end
          currentDE.delete('columns')
          multiDE.push(currentDE.dup)
        end

        @props = multiDE
      else
        @props['Fields'] = {}
        @props['Fields']['Field'] = []

        @columns.each do |key|
          @props['Fields']['Field'].push(key)
        end
      end

      obj = super
      @props = originalProps
      obj
    end

    def patch
      @props['Fields'] = {}
      @props['Fields']['Field'] = []
      @columns.each do |key|
        @props['Fields']['Field'].push(key)
      end
      obj = super
      @props.delete('Fields')
      obj
    end

    class Column < ET_GetSupport
      def initialize
        super
        @obj = 'DataExtensionField'
      end

      def get
        @props = props if props&.is_a?(Array)

        @props = @props.keys if @props&.is_a?(Hash)

        @filter = filter if filter&.is_a?(Hash)

        fixCustomerKey = false
        if filter&.is_a?(Hash)
          @filter = filter
          if @filter.key?('Property') && @filter['Property'] == 'CustomerKey'
            @filter['Property'] = 'DataExtension.CustomerKey'
            fixCustomerKey = true
          end
        end

        obj = ET_Get.new(@authStub, @obj, @props, @filter)
        @lastRequestID = obj.request_id

        @filter['Property'] = 'CustomerKey' if fixCustomerKey

        obj
      end
    end

    class Row < ET_CUDSupport
      attr_accessor :Name, :CustomerKey

      def initialize
        super
        @obj = 'DataExtensionObject'
      end

      def get
        getName
        @props = props if props&.is_a?(Array)

        @props = @props.keys if @props&.is_a?(Hash)

        @filter = filter if filter&.is_a?(Hash)

        obj = ET_Get.new(@authStub, "DataExtensionObject[#{@Name}]", @props, @filter)
        @lastRequestID = obj.request_id

        obj
      end

      def post
        getCustomerKey
        originalProps = @props
        ## FIX THIS
        if @props.is_a? Array
        #           multiRow = []
        #           @props.each { |currentDE|
        #
        #             currentDE['columns'].each { |key|
        #               currentDE['Fields'] = {}
        #               currentDE['Fields']['Field'] = []
        #               currentDE['Fields']['Field'].push(key)
        #             }
        #             currentDE.delete('columns')
        #             multiRow.push(currentDE.dup)
        #           }
        #
        #           @props = multiRow
        else
          currentFields = []
          currentProp = {}

          @props.each do |key, value|
            currentFields.push('Name' => key, 'Value' => value)
          end
          currentProp['CustomerKey'] = @CustomerKey
          currentProp['Properties'] = {}
          currentProp['Properties']['Property'] = currentFields
        end

        obj = ET_Post.new(@authStub, @obj, currentProp)
        @props = originalProps
        obj
      end

      def patch
        getCustomerKey
        currentFields = []
        currentProp = {}

        @props.each do |key, value|
          currentFields.push('Name' => key, 'Value' => value)
        end
        currentProp['CustomerKey'] = @CustomerKey
        currentProp['Properties'] = {}
        currentProp['Properties']['Property'] = currentFields

        ET_Patch.new(@authStub, @obj, currentProp)
      end

      def delete
        getCustomerKey
        currentFields = []
        currentProp = {}

        @props.each do |key, value|
          currentFields.push('Name' => key, 'Value' => value)
        end
        currentProp['CustomerKey'] = @CustomerKey
        currentProp['Keys'] = {}
        currentProp['Keys']['Key'] = currentFields

        ET_Delete.new(@authStub, @obj, currentProp)
      end

      private

      def getCustomerKey
        if @CustomerKey.nil?
          if @CustomerKey.nil? && @Name.nil?
            raise 'Unable to process DataExtension::Row request due to CustomerKey and Name not being defined on ET_DatExtension::row'
          else
            de = ET_DataExtension.new
            de.authStub = @authStub
            de.props = %w[Name CustomerKey]
            de.filter = { 'Property' => 'CustomerKey', 'SimpleOperator' => 'equals', 'Value' => @Name }
            getResponse = de.get
            if getResponse.status && (getResponse.results.length == 1)
              @CustomerKey = getResponse.results[0][:customer_key]
            else
              raise 'Unable to process DataExtension::Row request due to unable to find DataExtension based on Name'
            end
          end
        end
      end

      def getName
        if @Name.nil?
          if @CustomerKey.nil? && @Name.nil?
            raise 'Unable to process DataExtension::Row request due to CustomerKey and Name not being defined on ET_DatExtension::row'
          else
            de = ET_DataExtension.new
            de.authStub = @authStub
            de.props = %w[Name CustomerKey]
            de.filter = { 'Property' => 'CustomerKey', 'SimpleOperator' => 'equals', 'Value' => @CustomerKey }
            getResponse = de.get
            if getResponse.status && (getResponse.results.length == 1)
              @Name = getResponse.results[0][:name]
            else
              raise 'Unable to process DataExtension::Row request due to unable to find DataExtension based on CustomerKey'
            end
          end
        end
      end
    end
  end

  class ET_List < ET_CUDSupport
    def initialize
      super
      @obj = 'List'
    end

    class Subscriber < ET_GetSupport
      def initialize
        super
        @obj = 'ListSubscriber'
      end
    end
  end

  class ET_Email < ET_CUDSupport
    def initialize
      super
      @obj = 'Email'
    end
  end

  class ET_TriggeredSend < ET_CUDSupport
    attr_accessor :subscribers, :attributes
    def initialize
      super
      @obj = 'TriggeredSendDefinition'
    end

    def send
      @tscall = { 'TriggeredSendDefinition' => @props, 'Subscribers' => @subscribers, 'Attributes' => @attributes }
      ET_Post.new(@authStub, 'TriggeredSend', @tscall)
    end
  end

  class ET_ContentArea < ET_CUDSupport
    def initialize
      super
      @obj = 'ContentArea'
    end
  end

  class ET_Folder < ET_CUDSupport
    def initialize
      super
      @obj = 'DataFolder'
    end
  end

  class ET_SentEvent < ET_GetSupport
    def initialize
      super
      @obj = 'SentEvent'
    end
  end

  class ET_OpenEvent < ET_GetSupport
    def initialize
      super
      @obj = 'OpenEvent'
    end
  end

  class ET_BounceEvent < ET_GetSupport
    def initialize
      super
      @obj = 'BounceEvent'
    end
  end

  class ET_UnsubEvent < ET_GetSupport
    def initialize
      super
      @obj = 'UnsubEvent'
    end
  end

  class ET_ClickEvent < ET_GetSupport
    def initialize
      super
      @obj = 'ClickEvent'
    end
  end
end
