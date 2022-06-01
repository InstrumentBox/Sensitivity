//
//  OnDeviceKeychain.swift
//
//  Copyright © 2022 Aleksei Zaikin.
//
//  Permission is hereby granted, free of charge, to any person obtaining a copy
//  of this software and associated documentation files (the "Software"), to deal
//  in the Software without restriction, including without limitation the rights
//  to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
//  copies of the Software, and to permit persons to whom the Software is
//  furnished to do so, subject to the following conditions:
//
//  The above copyright notice and this permission notice shall be included in
//  all copies or substantial portions of the Software.
//
//  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
//  IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
//  FITNESS FOR A PARTICULAR PURPOSE AND NON-INFRINGEMENT. IN NO EVENT SHALL THE
//  AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
//  LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
//  OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
//  THE SOFTWARE.
//

import Foundation

public enum OnDeviceKeychainError: Error {
   case notFound
   case duplication
   case other(OSStatus)
   case unexpectedResult
}

// MARK: -

public final class OnDeviceKeychain: Keychain {
   private let accessGroupName: String?

   // MARK: - Init

   public init(accessGroupName: String?) {
      self.accessGroupName = accessGroupName
   }

   // MARK: - Keychain

   public func save<Query: Sensitivity.Query>(
      _ item: Query.Converter.Item,
      with query: Query
   ) throws {
      let valueData = try query.converter.convert(item)
      let queryDict = makeQueryDict(basedOn: query, returnsData: false, valueData: valueData)

      do {
         let status = SecItemAdd(queryDict, nil)
         try processStatus(status)
      } catch OnDeviceKeychainError.duplication {
         let status = SecItemUpdate(queryDict, queryDict)
         try processStatus(status)
      } catch {
         throw error
      }
   }

   public func fetch<Query: Sensitivity.Query>(with query: Query) throws -> Query.Converter.Item {
      let queryDict = makeQueryDict(basedOn: query, returnsData: true, valueData: nil)

      var any: AnyObject?
      try withUnsafeMutablePointer(to: &any) { p in
         let status = SecItemCopyMatching(queryDict, UnsafeMutablePointer(p))
         try processStatus(status)
      }

      guard let data = any as? Data else {
         throw OnDeviceKeychainError.unexpectedResult
      }

      return try query.converter.convert(data)
   }

   public func delete<Query: Sensitivity.Query>(with query: Query) throws {
      let queryDict = makeQueryDict(basedOn: query, returnsData: false, valueData: nil)

      let status = SecItemDelete(queryDict)
      try processStatus(status)
   }

   // MARK: - Private

   private func makeQueryDict<Query: Sensitivity.Query>(
      basedOn query: Query,
      returnsData: Bool,
      valueData: Data?
   ) -> CFDictionary {
      var queryDict: [CFString: Any] = [
         kSecClass: kSecClassGenericPassword,
         kSecAttrAccessible: kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly,
         kSecAttrService: query.service,
         kSecAttrAccount: query.account
      ]

      if returnsData {
         queryDict[kSecReturnData] = kCFBooleanTrue
         queryDict[kSecMatchLimit] = kSecMatchLimitOne
      }

      queryDict[kSecAttrAccessGroup] = accessGroupName
      queryDict[kSecValueData] = valueData

      return queryDict as CFDictionary
   }

   private func processStatus(_ status: OSStatus) throws {
      switch status {
         case errSecSuccess:
            break
         case errSecItemNotFound:
            throw OnDeviceKeychainError.notFound
         case errSecDuplicateItem:
            throw OnDeviceKeychainError.duplication
         default:
            throw OnDeviceKeychainError.other(status)
      }
   }
}
