# Menu Title: VirustTotal Integration
# Needs Case: true
# Needs Selected Items: true
# @version 1.0.0

API_KEY = ''
URL = 'http://www.virustotal.com/vtapi/v2/file/report'
requests_per_minute = 4 # public API provides 4 requests/minute

require 'json'
require 'net/http'
require 'uri'
# Nx Bootstrap
require File.join(__dir__, 'Nx.jar')
java_import 'com.nuix.nx.NuixConnection'
java_import 'com.nuix.nx.LookAndFeelHelper'
java_import 'com.nuix.nx.dialogs.ChoiceDialog'
java_import 'com.nuix.nx.dialogs.CommonDialogs'
java_import 'com.nuix.nx.dialogs.ProcessingStatusDialog'
java_import 'com.nuix.nx.dialogs.ProgressDialog'
java_import 'com.nuix.nx.dialogs.TabbedCustomDialog'
java_import 'com.nuix.nx.digest.DigestHelper'
java_import 'com.nuix.nx.controls.models.Choice'
LookAndFeelHelper.setWindowsIfMetal
NuixConnection.setUtilities($utilities)
NuixConnection.setCurrentNuixVersion(NUIX_VERSION)

selected_count = $current_selected_items.size
discovered = 0
errors = {}
last_req = nil
SLEEP_TIME = (60.0 / requests_per_minute).ceil

ProgressDialog.forBlock do |progress_dialog|
  progress_dialog.setTitle('VirusTotal Integration')
  progress_dialog.setLogVisible(true)
  progress_dialog.setTimestampLoggedMessages(true)
  progress_dialog.setMainStatusAndLogIt("#{selected_count} items selected")
  progress_dialog.setMainProgress(0, selected_count)
  $current_selected_items.each_with_index do |item, index|
    # wait between requests due to API limits
    unless last_req.nil?
      sleep_for = (SLEEP_TIME - (Time.now - last_req)).ceil
      if sleep_for.positive?
        progress_dialog.setSubStatusAndLogIt("Waiting #{SLEEP_TIME} seconds between requests")
        # update sub progress while sleeping
        progress_dialog.setSubProgress(0, sleep_for)
        sleep_for.times do |i|
          sleep(1)
          progress_dialog.setSubProgress(i)
          break if progress_dialog.abortWasRequested
        end
      end
    end
    progress_dialog.setMainProgress(index)
    md5 = item.get_digests.get_md5
    progress_dialog.setSubStatusAndLogIt("Retrieving file scan reports for #{md5}")
    progress_dialog.setSubProgress(0)
    # get HTTP response
    uri = URI.parse(URL)
    params = { 'apikey' => API_KEY, 'resource' => md5 }
    uri.query = URI.encode_www_form(params)
    response = Net::HTTP.get_response(uri)
    last_req = Time.now
    if response.is_a? Net::HTTPOK
      json_data = JSON.parse(response.body)
      if json_data['response_code'] == 1
        discovered += 1
        progress_dialog.setSubStatus('Storing results')
        progress_dialog.logMessage("Positives: #{json_data['positives']}")
        cm = item.get_custom_metadata
        cm.put_integer('VirusTotal Hits', json_data['positives'])
        scans = json_data['scans']
        progress_dialog.setSubProgress(0, scans.size)
        scans.each_with_index do |(scanner, res), i|
          progress_dialog.setSubProgress(i)
          result = res['result']
          cm.putText("VirusTotal #{scanner}", result) unless result.nil?
          break if progress_dialog.abortWasRequested
        end
      else # respource not found
        progress_dialog.logMessage(json_data['verbose_msg'])
      end
    else # handle errors
      err = "#{response.code}: #{response.message}"
      errors[md5] = err
      case response
      when Net::HTTPUnauthorized, Net::HTTPForbidden
        err += '- invalid API key?'
      when Net::HTTPServerError
        err += '- try again later?'
      when Net::HTTPNotFound
        err += '- wrong URL?'
      when Net::HTTPNoContent
        err += '- exceeded API limit?'
      end
      progress_dialog.logMessage('ERROR ' + err)
    end
    break if progress_dialog.abortWasRequested
  end
  if progress_dialog.abortWasRequested
    progress_dialog.setMainStatusAndLogIt('Completed: User Aborted')
  else
    progress_dialog.logMessage("VirusTotal Search script has finished. #{discovered} / #{selected_count} found (#{errors.size} errors).")
    unless errors.empty?
      msg = 'Errors:'
      errors.each { |k, v| msg += "\n #{k} - #{v}" }
      progress_dialog.logMessage(msg)
    end
    progress_dialog.setCompleted
  end
end
