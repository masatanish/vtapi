require 'spec_helper'

describe VtAPI do
  before do
    #RestClient.log = STDERR
  end

  let(:apikey) { 'test apikey' }
  let(:api) { VtAPI.new(apikey) }
  subject { api }

  describe '#apikey' do
    it { expect(subject.apikey).to eq apikey }
  end

  describe '#file_scan' do
    let(:sample_response) { '{}' }
    let(:api_url) { 'https://www.virustotal.com/vtapi/v2/file/scan' }
    subject { api.file_scan('binary data') }
    it "should connect to virustotal.com with 'multipart/form-data' Content-Type" do
      stub_request(:post, api_url)
      .with(:headers => { "Content-Type" => /^multipart\/form-data;.*/ })
      .to_return(:body => sample_response)
      subject
    end
    it 'should include data part in body' do
      stub_request(:post, api_url)
      .with(:body => /name="file"; filename="tmp.*\r\n/ )
      .to_return(:body => sample_response)
      subject
    end
    it 'should include posted binary data in body' do
      stub_request(:post, api_url)
      .with(:body => /binary data/ )
      .to_return(:body => sample_response)
      subject
    end
  end

  describe '#file_rescan' do
    let(:sample_response) { '{}' }
    let(:api_url) { 'https://www.virustotal.com/vtapi/v2/file/rescan' }
    let(:resource) { 'ff' * 32 }
    subject { api.file_rescan(resource) }
    it "should connect to 'https://www.virustotal.com/vtapi/v2/file/rescan'" do
      stub_request(:post, api_url)
      .with(:body => {'resource' => resource, 'apikey' => apikey} )
      .to_return(:body => sample_response, :status => 200)
      subject
    end

    context 'assigns 2 resources' do
      let(:resource) { ['ff' * 32, '00' * 32] }
      let(:sample_response) { '[{}]' }
      it "should post resource parameter as comma separete value" do
        stub_request(:post, api_url)
        .with(:body => {'resource' => resource.join(', '), 'apikey' => apikey} )
        .to_return(:body => sample_response, :status => 200)
        subject
      end
    end

    context 'when assign 25 resources(over the limitation)' do
      let(:resource) { ['ff' * 32] * 25 }
      it { expect{ subject }.to raise_error }
    end
  end

  describe '#file_report' do
    let(:sample_response) { '{}' }
    let(:api_url) { 'https://www.virustotal.com/vtapi/v2/file/report' }
    let(:resource) { 'ff' * 32 }
    subject { api.file_report(resource) }
    it "should connect to 'https://www.virustotal.com/vtapi/v2/file/report'" do
      stub_request(:post, api_url)
      .with(:body => {'resource' => resource, 'apikey' => apikey} )
      .to_return(:body => sample_response, :status => 200)
      subject
    end

    context 'when server returns 204' do
      it do
        stub_request(:post, api_url).to_return(:status => 204)
        expect{ subject }.to raise_error(VtAPI::ExceedAPILimit)
      end
    end
    context 'when server returns 403' do
      it do
        stub_request(:post, api_url).to_return(:status => 403)
        expect{ subject }.to raise_error(VtAPI::AuthError)
      end
    end

    context 'when assign 2 resources' do
      let(:resource) { ['ff' * 32, '00' * 32] }
      it "should post resource parameter as comma separete value" do
        stub_request(:post, api_url)
        .with(:body => {'resource' => resource.join(', '), 'apikey' => apikey} )
        .to_return(:body => sample_response, :status => 200)
        subject
      end
    end

    context 'when assign 5 resources(over the limitation)' do
      let(:resource) { ['ff' * 32] * 5 }
      it { expect{ subject }.to raise_error }
    end
  end

  describe '#url_scan' do
    let(:sample_response) { '{}' }
    let(:api_url) { 'https://www.virustotal.com/vtapi/v2/url/scan' }
    let(:target_url) { 'http://www.foobar.com/' }
    subject { api.url_scan(target_url) }

    it "should connect to 'https://www.virustotal.com/vtapi/v2/url/scan'" do
      stub_request(:post, api_url)
      .with(:body => {'url' => target_url, 'apikey' => apikey} )
      .to_return(:body => sample_response, :status => 200)
      subject
    end

    context 'when assign 2 urls' do
      let(:target_url) { ['http://foobar.com/', 'http://abc.com'] }

      it "should post url parameter which is joined by '\\n'" do
        stub_request(:post, api_url)
        .with(:body => {'url' => target_url.join("\n"), 'apikey' => apikey} )
        .to_return(:body => sample_response, :status => 200)
        subject
      end
    end

    context 'when assign 5 urls (over the limitation)' do
      let(:target_url) { ['http://www.foobar.com/'] * 5 }

      it { expect{ subject }.to raise_error }
    end
  end

  describe '#url_report' do
    let(:sample_response) { '{}' }
    let(:api_url) { 'https://www.virustotal.com/vtapi/v2/url/report' }
    let(:target_url) { 'http://www.foobar.com/' }
    subject { api.url_report(target_url) }

    it "should connect to 'https://www.virustotal.com/vtapi/v2/url/report'" do
      stub_request(:post, api_url)
      .with(:body => {'resource' => target_url, 'apikey' => apikey} )
      .to_return(:body => sample_response, :status => 200)
      subject
    end

    context 'when assign 2 urls' do
      let(:target_url) { ['http://foobar.com/', 'http://abc.com'] }

      it "should post url parameter which is joined by ', '" do
        stub_request(:post, api_url)
        .with(:body => {'resource' => target_url.join(", "), 'apikey' => apikey} )
        .to_return(:body => sample_response, :status => 200)
        subject
      end
    end

    context 'when assign 5 urls (over the limitation)' do
      let(:target_url) { ['http://www.foobar.com/'] * 5 }

      it { expect{ subject }.to raise_error }
    end
  end

  describe '#ip_report' do
    let(:sample_response) { '{}' }
    let(:api_url) { 'https://www.virustotal.com/vtapi/v2/ip-address/report?apikey=test%20apikey&ip=8.8.8.8' }
    let(:target_ip) { '8.8.8.8' }
    subject { api.ip_report(target_ip) }

    it "should connect to 'https://www.virustotal.com/vtapi/v2/ip-address/report?apikey=test%20apikey&ip=8.8.8.8'" do
      stub_request(:get, api_url)
      .to_return(:body => sample_response, :status => 200)
      subject
    end
  end

  describe '#domain_report' do
    let(:sample_response) { '{}' }
    let(:api_url) { 'https://www.virustotal.com/vtapi/v2/domain/report?apikey=test%20apikey&domain=8.8.8.8' }
    let(:target_domain) { '8.8.8.8' }
    subject { api.domain_report(target_domain) }

    it "should connect to 'https://www.virustotal.com/vtapi/v2/domain/report?apikey=test%20apikey&domain=8.8.8.8'" do
      stub_request(:get, api_url)
      .to_return(:body => sample_response, :status => 200)
      subject
    end
  end
end
