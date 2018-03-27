# frozen_string_literal: true

require 'marketingcloudsdk'
require_relative 'sample_helper'

begin
  myclient = MarketingCloudSDK::Client.new auth
  ListID = '1956035'
  CSVFileName = 'SDKExample.csv'

  #   * Parameters:
  #     * List ID
  #     * File Name - File must be a CSV located on your ExactTarget FTP Site

  response = myclient.CreateAndStartListImport(ListID, CSVFileName)
  p 'Response Status: ' + response.status.to_s
  p 'Code: ' + response.code.to_s
  p 'Message: ' + response.message.to_s
  p 'Results Length: ' + response.results.length.to_s
  p 'Results: ' + response.results.to_s
rescue StandardError => e
  p "Caught exception: #{e.message}"
  p e.backtrace
end
