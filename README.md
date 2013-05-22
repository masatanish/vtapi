# VtAPI

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

### File Upload
```ruby
# read file
data = File.open(some_path, 'rb') {|f| f.read }

# upload data
resp = api.file_scan(data)

# confirm response_code
puts resp.response_code # 1: OK, 0: result doesn't exist, -2: still queued
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


