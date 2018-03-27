# frozen_string_literal: true

require 'marketingcloudsdk'
require_relative 'sample_helper' # contains auth with credentials

begin
  filter = { 'Property' => 'Type', 'SimpleOperator' => 'equals', 'Value' => 'Public' }
  client = ET_Client.new auth
  getResponse = ET_Get.new client, 'List', nil, filter
  p "Get Status: #{getResponse.status}"
  p "Code: #{getResponse.code}"
  p "Message: #{getResponse.message}"
  p "Result Count: #{getResponse.results.length}"
  p "Results: #{getResponse.results.inspect}"
  raise 'Failure getting List info' unless getResponse.success?

  NewListName = 'RubySDKList'
  props = { 'ListName' => NewListName, 'Description' => 'This list was created with the RubySDK', 'Type' => 'Private' }
  client = ET_Client.new auth
  postResponse = ET_Post.new client, 'List', props
  p "Post Status: #{postResponse.status}"
  p "Code: #{postResponse.code}"
  p "Message: #{postResponse.message}"
  p "Result Count: #{postResponse.results.length}"
  p "Results: #{postResponse.results.inspect}"
  raise 'Failure Creating List' unless postResponse.success?

  if postResponse.success?
    newListID = postResponse.results[0][:new_id]
    p "New ID: #{newListID}"

    props = { 'ID' => newListID, 'Description' => 'Update!!!' }
    client = ET_Client.new auth
    patchResponse = ET_Patch.new client, 'List', props
    p "Patch Status: #{patchResponse.status}"
    p "Code: #{patchResponse.code}"
    p "Message: #{patchResponse.message}"
    p "Result Count: #{patchResponse.results.length}"
    p "Results: #{patchResponse.results.inspect}"
    raise 'Failure Patching List' unless patchResponse.success?

    props = { 'ID' => newListID }
    client = ET_Client.new auth
    deleteResponse = ET_Delete.new client, 'List', props
    p "Delete Status: #{deleteResponse.status}"
    p "Code: #{deleteResponse.code}"
    p "Message: #{deleteResponse.message}"
    p "Result Count: #{deleteResponse.results.length}"
    p "Results: #{deleteResponse.results.inspect}"
    raise 'Failure Deleting List' unless deleteResponse.success?
  end
rescue StandardError => e
  p "Caught exception: #{e.message}"
  p e.backtrace
end
