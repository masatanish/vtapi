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
      .with(:body => /name="data"\r\n/ )
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
  describe '#file_report' do
    let(:sample_response) { '{}' }
    let(:api_url) { 'https://www.virustotal.com/vtapi/v2/file/report' }
    let(:resource) { 'ff' * 32 }
    subject { api.file_report(resource) }
    it "should connect to 'https://www.virustotal.com/vtapi/v2/file/report'" do
      stub_request(:post, api_url)
      .with(:body => {'resource' => resource, 'apikey' => apikey} )
      .to_return(:body => sample_response)
      subject
    end
  end
end
