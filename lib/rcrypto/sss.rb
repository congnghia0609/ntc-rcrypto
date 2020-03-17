require 'base64'

module Rcrypto
  class SSS
    # The largest PRIME 256-bit big.Int
    # https://primes.utm.edu/lists/2small/200bit.html
    # PRIME = 2^n - k = 2^256 - 189
    @@prime = 115792089237316195423570985008687907853269984665640564039457584007913129639747

    # Returns a random number from the range (0, PRIME-1) inclusive
    def random_number
      rand(1...@@prime)
    end

    # extended gcd
    def egcd(a, b)
      if a == 0
        return b, 0, 1
      else
        g, y, x = egcd(b % a, a)
        return g, x - (b / a) * y, y
      end
    end

    # Computes the multiplicative inverse of the number on the field PRIME.
    def modinv(a, m)
      g, x, y = egcd(a, m)
      if g != 1
        raise Exception('modular inverse does not exist')
      else
        return x % m
      end
    end

    # Convert string to hex.
    def hexlify(s)
      a = []
      if s.respond_to? :each_byte
        s.each_byte { |b| a << sprintf('%02X', b) }
      else
        s.each { |b| a << sprintf('%02X', b) }
      end
      a.join.downcase
    end

    # Convert hex to string.
    def unhexlify(s)
      s.split.pack('H*')
    end

    # Returns the Int number base10 in base64 representation; note: this is
    # not a string representation; the base64 output is exactly 256 bits long.
    def to_base64(number)
      hexdata = number.to_s(16)
      n = 64 - hexdata.length
      i = 0
      while i < n
        hexdata = '0' + hexdata
        i += 1
      end
      b64data = Base64.urlsafe_encode64(hexdata)
      b64data
    end

    # Returns the number base64 in base 10 Int representation; note: this is
    # not coming from a string representation; the base64 input is exactly 256
    # bits long, and the output is an arbitrary size base 10 integer.
    def from_base64(number)
      hexdata = Base64.urlsafe_decode64(number)
      rs = hexdata.to_i(16)
      rs
    end

    # Returns the Int number base10 in Hex representation; note: this is
    # not a string representation; the Hex output is exactly 256 bits long.
    def to_hex(number)
      hexdata = number.to_s(16)
      # puts hexdata
      n = 64 - hexdata.length
      i = 0
      while i < n
        hexdata = '0' + hexdata
        i += 1
      end
      hexdata
    end

    # Returns the number Hex in base 10 Int representation; note: this is
    # not coming from a string representation; the Hex input is exactly 256
    # bits long, and the output is an arbitrary size base 10 integer.
    def from_hex(number)
      rs = number.to_i(16)
      rs
    end

    # Evaluates a polynomial with coefficients specified in reverse order:
    #  evaluatePolynomial([a, b, c, d], x):
    #  		return a + bx + cx^2 + dx^3
    #  Horner's method: ((dx + c)x + b)x + a
    def evaluate_polynomial(polynomial, part, value)
      last = polynomial[part].length - 1
      result = polynomial[part][last]
      s = last - 1
      while s >= 0
        result = (result * value + polynomial[part][s]) % @@prime
        s -= 1
      end
      result
    end

    # Converts a byte array into an a 256-bit Int, array based upon size of
    # the input byte; all values are right-padded to length 256, even if the most
    # significant bit is zero.
    def split_secret_to_int(secret)
      result = []
      hex_data = hexlify(secret)
      count = (hex_data.length / 64.0).ceil
      i = 0
      while i < count
        if (i + 1) * 64 < hex_data.length
          subs = hex_data[i * 64...(i + 1) * 64]
          result.append(subs.to_i(16))
        else
          last = hex_data[i * 64...hex_data.length]
          n = 64 - last.length
          j = 0
          while j < n
            last += '0'
            j += 1
          end
          result.append(last.to_i(16))
        end
        i += 1
      end
      result
    end

    def trim_right(s)
      i = s.length - 1
      while i >= 0 && s[i] == '0'
        i -= 1
      end
      rs = s[0..i]
      rs
    end

    # Converts an array of Ints to the original byte array, removing any
    # least significant nulls.
    def merge_int_to_string(secrets)
      hex_data = ""
      for s in secrets
        tmp = to_hex(s)
        hex_data += tmp
      end
      hex_data = unhexlify(trim_right(hex_data))
      hex_data
    end

    # in_numbers(numbers, value) returns boolean whether or not value is in array
    def in_numbers(numbers, value)
      for n in numbers
        if n == value
          return true
        end
      end
      return false
    end

    # Returns a new array of secret shares (encoding x,y pairs as Base64 or Hex strings)
    # created by Shamir's Secret Sharing Algorithm requiring a minimum number of
    # share to recreate, of length shares, from the input secret raw as a string.
    def create(minimum, shares, secret)
      result = []

      # Verify minimum isn't greater than shares; there is no way to recreate
      # the original polynomial in our current setup, therefore it doesn't make
      # sense to generate fewer shares than are needed to reconstruct the secrets.
      if minimum > shares
        raise Exception('cannot require more shares then existing')
      end

      # Convert the secrets to its respective 256-bit Int representation.
      secrets = split_secret_to_int(secret)

      # List of currently used numbers in the polynomial
      numbers = [0]

      # Create the polynomial of degree (minimum - 1); that is, the highest
      # order term is (minimum-1), though as there is a constant term with
      # order 0, there are (minimum) number of coefficients.
      #
      # However, the polynomial object is a 2d array, because we are constructing
      # a different polynomial for each part of the secrets.
      #
      # polynomial[parts][minimum]
      polynomial = []
      for i in 0...secrets.length
        subpoly = []
        subpoly.push(secrets[i])
        j = 1
        while j < minimum
          # Each coefficient should be unique
          number = random_number()
          while in_numbers(numbers, number)
            number = random_number()
          end

          numbers.append(number)
          subpoly.push(number)
          j += 1
        end
        polynomial.push(subpoly)
      end

      # Create the points object; this holds the (x, y) points of each share.
      # Again, because secrets is an array, each share could have multiple parts
      # over which we are computing Shamir's Algorithm. The last dimension is
      # always two, as it is storing an x, y pair of points.
      #
      # Note: this array is technically unnecessary due to creating result
      # in the inner loop. Can disappear later if desired.
      #
      # points[shares][parts][2]
      points = []
      for i in 0...shares
        s = ''
        arrsh = []
        for j in 0...secrets.length
          arrxy = []
          # generate a new x-coordinate.
          number = random_number()
          while in_numbers(numbers, number)
            number = random_number()
          end
          x = number
          y = evaluate_polynomial(polynomial, j, number)
          arrxy.push(x)
          arrxy.push(y)
          s += to_hex(x)
          s += to_hex(y)
          arrsh.push(arrxy)
        end
        points.push(arrsh)
        result.push(s)
      end
      result
    end

    # akes a string array of shares encoded in Hex created via Shamir's
    # Algorithm; each string must be of equal length of a multiple of 128 characters
    # as a single 128 character share is a pair of 256-bit numbers (x, y).
    def decode_share_hex(shares)
      # Recreate the original object of x, y points, based upon number of shares
      # and size of each share (number of parts in the secret).
      secrets = []

      # For each share...
      for i in 0...shares.length
        # ensure that it is valid.
        unless is_valid_share_hex(shares[i])
          raise Exception('one of the shares is invalid')
        end

        # find the number of parts it represents.
        share = shares[i]
        count = share.length / 128
        arrsh = []
        # and for each part, find the x,y pair...
        for j in 0...count
          cshare = share[j * 128...(j + 1) * 128]
          arrxy = []
          # decoding from Base64.
          x = from_hex(cshare[0...64])
          y = from_hex(cshare[64...128])
          arrxy.push(x)
          arrxy.push(y)
          arrsh.push(arrxy)
        end
        secrets.push(arrsh)
      end
      secrets
    end

    # Takes in a given string to check if it is a valid secret
    #
    # Requirements:
    #  	Length multiple of 128
    # 	Can decode each 64 character block as Hex
    #
    # Returns only success/failure (bool)
    def is_valid_share_hex(candidate)
      if candidate.length == 0 || candidate.length % 128 != 0
        return false
      end
      count = candidate.length / 64
      j = 0
      while j < count
        part = candidate[j * 64...(j + 1) * 64]
        decode = from_hex(part)
        if decode < 0 || decode == @@prime
          return false
        end
        j += 1
      end
      return true
    end

    # Takes a string array of shares encoded in Base64 or Hex created via Shamir's Algorithm
    #     Note: the polynomial will converge if the specified minimum number of shares
    #           or more are passed to this function. Passing thus does not affect it
    #           Passing fewer however, simply means that the returned secret is wrong.
    def combine(shares)
      if shares.empty?
        raise Exception('shares is NULL or empty')
      end

      # Recreate the original object of x, y points, based upon number of shares
      # and size of each share (number of parts in the secret).
      #
      # points[shares][parts][2]
      points = decode_share_hex(shares)
      # puts points

      # Use Lagrange Polynomial Interpolation (LPI) to reconstruct the secrets.
      # For each part of the secrets (clearest to iterate over)...
      secrets = []
      for j in 0...(points[0]).length
        secrets.append(0)
        # and every share...
        for i in 0...shares.length  # LPI sum loop
          # remember the current x and y values.
          ax = points[i][j][0]  # ax
          ay = points[i][j][1]  # ay
          numerator = 1  # LPI numerator
          denominator = 1  # LPI denominator
          # and for every other point...
          for k in 0...shares.length  # LPI product loop
            if k != i
              # combine them via half products.
              # x=0 ==> [(0-bx)/(ax-bx)] * ...
              bx = points[k][j][0]  # bx
              negbx = -bx  # (0 - bx)
              axbx = ax - bx  # (ax - bx)

              numerator = (numerator * negbx) % @@prime  # (0 - bx) * ...
              denominator = (denominator * axbx) % @@prime  # (ax - bx) * ...
            end
          end
          # LPI product: x=0, y = ay * [(x-bx)/(ax-bx)] * ...
          # multiply together the points (ay)(numerator)(denominator)^-1 ...
          fx = ay
          fx = (fx * numerator) % @@prime
          fx = (fx * modinv(denominator, @@prime)) % @@prime

          # LPI sum: s = fx + fx + ...
          secrets[j] = (secrets[j] + fx) % @@prime
        end
      end
      rs = merge_int_to_string(secrets)
      rs
    end

  end
end
