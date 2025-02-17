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
      a = s.encode("UTF-8").bytes.map { |b| b.to_s(16) }
      a.join.downcase
    end

    # Convert hex to string.
    def unhexlify(s)
      s.split.pack('H*').force_encoding("UTF-8")
    end

    # Return Uint8Array binary representation of hex string.
    def hex_to_u8b(hex)
      u8 = []
      hex = '0' + hex if hex.length.odd?
      len = hex.length / 2
      i = 0
      j = 0
      while i < len
        u8.append((hex[j...j + 2]).to_i(16))
        j += 2
        i += 1
      end
      # uint8_t
      u8b = u8.pack('C*')
      u8b
    end

    # Return hex string representation of Uint8Array binary.
    def u8b_to_hex(u8b)
      u8 = u8b.unpack('C*')
      hex = u8.map do |v|
        v.to_s(16).rjust(2, '0')
      end.join
      hex
    end

    # Returns the Int number base10 in base64 representation; note: this is
    # not a string representation; the base64 output is exactly 256 bits long.
    def to_base64(number)
      hex_data = number.to_s(16)
      n = 64 - hex_data.length
      i = 0
      while i < n
        hex_data = '0' + hex_data
        i += 1
      end
      u8b = hex_to_u8b(hex_data)
      b64_data = Base64.urlsafe_encode64(u8b)
      b64_data
    end

    # Returns the number base64 in base 10 Int representation; note: this is
    # not coming from a string representation; the base64 input is exactly 256
    # bits long, and the output is an arbitrary size base 10 integer.
    def from_base64(number)
      u8b = Base64.urlsafe_decode64(number)
      hex_data = u8b_to_hex(u8b)
      rs = hex_data.to_i(16)
      rs
    end

    # Returns the Int number base10 in Hex representation; note: this is
    # not a string representation; the Hex output is exactly 256 bits long.
    def to_hex(number)
      hex_data = number.to_s(16)
      # puts hex_data
      n = 64 - hex_data.length
      i = 0
      while i < n
        hex_data = '0' + hex_data
        i += 1
      end
      hex_data
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

    # Remove right doubled characters '0' (zero byte in hex)
    def trim_right_doubled_zero(s)
      last = s.length
      i = s.length - 1
      while i > 2
        if s[i] == '0' && s[i - 1] == '0'
          last = i - 1
        else
          break
        end
        i -= 2
      end
      if last == s.length
        s
      else
        s[0..(last-1)]
      end
    end

    # Converts an array of Ints to the original byte array, removing any
    # least significant nulls.
    def merge_int_to_string(secrets)
      hex_data = ''
      for s in secrets
        tmp = to_hex(s)
        hex_data += tmp
      end
      hex_data = unhexlify(trim_right_doubled_zero(hex_data))
      hex_data
    end

    # in_numbers(numbers, value) returns boolean whether or not value is in array
    def in_numbers(numbers, value)
      for n in numbers
        return true if n == value
      end
      false
    end

    # Takes a string array of shares encoded in Base64Url created via Shamir's
    # Algorithm; each string must be of equal length of a multiple of 88 characters
    # as a single 88 character share is a pair of 256-bit numbers (x, y).
    def decode_share_base64(shares)
      # Recreate the original object of x, y points, based upon number of shares
      # and size of each share (number of parts in the secret).
      secrets = []

      # For each share...
      for i in 0...shares.length
        # ensure that it is valid.
        unless is_valid_share_base64(shares[i])
          raise Exception('one of the shares is invalid')
        end

        # find the number of parts it represents.
        share = shares[i]
        count = share.length / 88
        arr_sh = []
        # and for each part, find the x,y pair...
        for j in 0...count
          pair = share[j * 88...(j + 1) * 88]
          arr_xy = []
          # decoding from Base64.
          x = from_base64(pair[0...44])
          y = from_base64(pair[44...88])
          arr_xy.push(x)
          arr_xy.push(y)
          arr_sh.push(arr_xy)
        end
        secrets.push(arr_sh)
      end
      secrets
    end

    # Takes in a given string to check if it is a valid secret
    #
    # Requirements:
    #  	Length multiple of 88
    # 	Can decode each 44 character block as Bas64Url
    #
    # Returns only success/failure (bool)
    def is_valid_share_base64(candidate)
      return false if candidate.length == 0 || candidate.length % 88 != 0

      count = candidate.length / 44
      j = 0
      while j < count
        part = candidate[j * 44...(j + 1) * 44]
        decode = from_base64(part)
        return false if decode <= 0 || decode >= @@prime

        j += 1
      end
      true
    end

    # Takes a string array of shares encoded in Hex created via Shamir's
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
        arr_sh = []
        # and for each part, find the x,y pair...
        for j in 0...count
          pair = share[j * 128...(j + 1) * 128]
          arr_xy = []
          # decoding from Hex.
          x = from_hex(pair[0...64])
          y = from_hex(pair[64...128])
          arr_xy.push(x)
          arr_xy.push(y)
          arr_sh.push(arr_xy)
        end
        secrets.push(arr_sh)
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
      return false if candidate.length == 0 || candidate.length % 128 != 0

      count = candidate.length / 64
      j = 0
      while j < count
        part = candidate[j * 64...(j + 1) * 64]
        decode = from_hex(part)
        return false if decode <= 0 || decode >= @@prime

        j += 1
      end
      return true
    end

    # Returns a new array of secret shares (encoding x,y pairs as Base64 or Hex strings)
    # created by Shamir's Secret Sharing Algorithm requiring a minimum number of
    # share to recreate, of length shares, from the input secret raw as a string.
    def create(minimum, shares, secret, is_base64 = false)
      result = []

      # Verify minimum isn't greater than shares; there is no way to recreate
      # the original polynomial in our current setup, therefore it doesn't make
      # sense to generate fewer shares than are needed to reconstruct the secrets.
      if minimum <= 0 || shares <= 0
        raise Exception('minimum or shares is invalid')
      end
      if minimum > shares
        raise Exception('cannot require more shares then existing')
      end
      raise Exception('secret is NULL or empty') if secret.empty?

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
        sub_poly = []
        sub_poly.push(secrets[i])
        j = 1
        while j < minimum
          # Each coefficient should be unique
          x = random_number()
          while in_numbers(numbers, x)
            x = random_number()
          end

          numbers.append(x)
          sub_poly.push(x)
          j += 1
        end
        polynomial.push(sub_poly)
      end

      # Create the points object; this holds the (x, y) points of each share.
      # Again, because secrets is an array, each share could have multiple parts
      # over which we are computing Shamir's Algorithm. The last dimension is
      # always two, as it is storing an x, y pair of points.
      #
      # Note: this array is technically unnecessary due to creating result
      # in the inner loop. Can disappear later if desired.
      for i in 0...shares
        s = ''
        for j in 0...secrets.length
          # generate a new x-coordinate.
          x = random_number()
          while in_numbers(numbers, x)
            x = random_number()
          end
          numbers.append(x)
          y = evaluate_polynomial(polynomial, j, x)
          if is_base64
            s += to_base64(x)
            s += to_base64(y)
          else
            s += to_hex(x)
            s += to_hex(y)
          end
        end
        result.push(s)
      end
      result
    end

    # Takes a string array of shares encoded in Base64 or Hex created via Shamir's Algorithm
    #     Note: the polynomial will converge if the specified minimum number of shares
    #           or more are passed to this function. Passing thus does not affect it
    #           Passing fewer however, simply means that the returned secret is wrong.
    def combine(shares, is_base64 = false)
      raise Exception('shares is NULL or empty') if shares.empty?

      # Recreate the original object of x, y points, based upon number of shares
      # and size of each share (number of parts in the secret).
      #
      # points[shares][parts][2]
      points = if is_base64
                 decode_share_base64(shares)
               else
                 decode_share_hex(shares)
               end
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
              numerator = (numerator * -bx) % @@prime  # (0 - bx) * ...
              denominator = (denominator * (ax - bx)) % @@prime  # (ax - bx) * ...
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
