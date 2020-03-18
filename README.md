# ntc-rcrypto
ntc-rcrypto is module ruby cryptography.

## Installation

Add this line to your application's Gemfile:

```ruby
gem 'ntc-rcrypto'
```

And then execute:
```ruby
bundle install
```

Or install it yourself as:
```ruby
gem install ntc-rcrypto
```

## 1. An implementation of Shamir's Secret Sharing Algorithm 256-bits in Ruby
### Usage
**Use encode/decode Hex**  
```ruby
require 'rcrypto'

sss = Rcrypto::SSS.new

s = "nghiatcxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
puts s
puts s.length
# creates a set of shares
arr = sss.create(3, 6, s)
# puts arr

# combines shares into secret
s1 = sss.combine(arr[0...3])
puts s1
puts s1.length

s2 = sss.combine(arr[3...6])
puts s2
puts s2.length

s3 = sss.combine(arr[1...5])
puts s3
puts s3.length
```

## License
This code is under the [Apache Licence v2](https://www.apache.org/licenses/LICENSE-2.0).  
