# VtAPI [![Gem Version](https://badge.fury.io/rb/vtapi.png)](http://badge.fury.io/rb/vtapi)

Ruby gem for VirusTotal Public API v2.0

https://www.virustotal.com/en/documentation/public-api/

## Installation

Add this line to your application's Gemfile:

    gem 'vtapi'

And then execute:

    $ bundle

Or install it yourself as:

    $ gem install vtapi

## Usage
### Prepare
```ruby
# initialize
api = VtAPI.new('-- Your API KEY--')
```

### File Report
```ruby
# retrieve file report by file hash(SHA256, SHA1, MD5)
resp = api.file_report('00ce460c8b337110912066f746731a916e85bf1d7f4b44f09ca3cc39f9b52a98')

puts resp.response_code # 1: OK, 0: result doesn't exist, -2: still queued

# resp is a instance of VtAPI::Response class
puts resp.positives  #  num of positives
puts resp.scan_results # {"McAfee"=>nil, "Symantec"=>"Android.ZertSecurity", ... }
```

### File Report (multiple resources)
```ruby
# retrieve file report by file hash(SHA256, SHA1, MD5)
# up to 4 resources can assign 
resources = ['00ce460c8b33711091206..', ..]
resps = api.file_report(resources)
resps.each do |r|
  puts "#{r.sha256}: #{r.positives} / #{r.total}" if r.response_code == 1
end
```
The following APIs are supported Posting multi resources(URLs).
* VtAPI#file_report
* VtAPI#file_rescan
* VtAPI#url_scan
* VtAPI#url_report


### File Scan (File Upload)
```ruby
# read file
data = File.open(some_path, 'rb') {|f| f.read }

# upload data
resp = api.file_scan(data)

# confirm response_code
puts resp.response_code # 1: OK, 0: result doesn't exist, -2: still queued
```


### URL Scan
```ruby
# upload url
resp = api.url_scan(url)

# confirm response_code
puts resp.response_code # 1: OK, 0: result doesn't exist, -2: still queued
```


### URL Report
```ruby
# upload url
resp = api.url_scan(url)

# confirm result
puts resp.scans
```


### Domain Report
```ruby
# domain
resp = api.domain_report(domain)

# confirm result
puts resp.detected_urls
```


### IP address Report
```ruby
# IP address
resp = api.ip_report(ip)

# confirm result
puts resp.detected_communicating_samples
```


## Features
### Support API
* file/scan
* file/resan
* file/report
* url/scan
* url/report
* domain/report
* ip-address/report

### Unsupported
* comments/puts


## Contributing

1. Fork it
2. Create your feature branch (`git checkout -b my-new-feature`)
3. Commit your changes (`git commit -am 'Add some feature'`)
4. Push to the branch (`git push origin my-new-feature`)
5. Create new Pull Request


