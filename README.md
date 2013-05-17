# Vtapi
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
### File Report
```ruby
# initialize
api = VtAPI.new('-- Your API KEY--')

# retrieve file report by file hash
resp = api.file_report('00ce460c8b337110912066f746731a916e85bf1d7f4b44f09ca3cc39f9b52a98') 

# resp is a instance of VtAPI::Response class
puts resp.positives  #  num of positives
puts resp.response_code # 1: OK, 0: result doesn't exist, -2: still queued
puts resp.scan_results # {"McAfee"=>nil, "Symantec"=>"Android.ZertSecurity", ... }
```

## Features
### Supported API
* file/scan
* file/resan
* file/report

### not implemented yet
* url/scan
* url/report
* ip-address/report
* domain/report

### unsupported API
* comments/puts

## Contributing

1. Fork it
2. Create your feature branch (`git checkout -b my-new-feature`)
3. Commit your changes (`git commit -am 'Add some feature'`)
4. Push to the branch (`git push origin my-new-feature`)
5. Create new Pull Request

