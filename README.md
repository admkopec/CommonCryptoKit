# 🔐 CommonCryptoKit
![Platforms](https://img.shields.io/badge/platform-ios%20%7C%20tvos%20%7C%20watchos%20%7C%20macos-lightgrey)
[![GitHub](https://img.shields.io/badge/license-MIT-green)](LICENSE)
[![Swift Package Manager](https://img.shields.io/badge/package%20manager-compatible-brightgreen.svg?logo=data:image/svg+xml;base64,PD94bWwgdmVyc2lvbj0iMS4wIiBlbmNvZGluZz0iVVRGLTgiPz4KPHN2ZyB3aWR0aD0iNjJweCIgaGVpZ2h0PSI0OXB4IiB2aWV3Qm94PSIwIDAgNjIgNDkiIHZlcnNpb249IjEuMSIgeG1sbnM9Imh0dHA6Ly93d3cudzMub3JnLzIwMDAvc3ZnIiB4bWxuczp4bGluaz0iaHR0cDovL3d3dy53My5vcmcvMTk5OS94bGluayI+CiAgICA8IS0tIEdlbmVyYXRvcjogU2tldGNoIDYzLjEgKDkyNDUyKSAtIGh0dHBzOi8vc2tldGNoLmNvbSAtLT4KICAgIDx0aXRsZT5Hcm91cDwvdGl0bGU+CiAgICA8ZGVzYz5DcmVhdGVkIHdpdGggU2tldGNoLjwvZGVzYz4KICAgIDxnIGlkPSJQYWdlLTEiIHN0cm9rZT0ibm9uZSIgc3Ryb2tlLXdpZHRoPSIxIiBmaWxsPSJub25lIiBmaWxsLXJ1bGU9ImV2ZW5vZGQiPgogICAgICAgIDxnIGlkPSJHcm91cCIgZmlsbC1ydWxlPSJub256ZXJvIj4KICAgICAgICAgICAgPHBvbHlnb24gaWQ9IlBhdGgiIGZpbGw9IiNEQkI1NTEiIHBvaW50cz0iNTEuMzEwMzQ0OCAwIDEwLjY4OTY1NTIgMCAwIDEzLjUxNzI0MTQgMCA0OSA2MiA0OSA2MiAxMy41MTcyNDE0Ij48L3BvbHlnb24+CiAgICAgICAgICAgIDxwb2x5Z29uIGlkPSJQYXRoIiBmaWxsPSIjRjdFM0FGIiBwb2ludHM9IjI3IDI1IDMxIDI1IDM1IDI1IDM3IDI1IDM3IDE0IDI1IDE0IDI1IDI1Ij48L3BvbHlnb24+CiAgICAgICAgICAgIDxwb2x5Z29uIGlkPSJQYXRoIiBmaWxsPSIjRUZDNzVFIiBwb2ludHM9IjEwLjY4OTY1NTIgMCAwIDE0IDYyIDE0IDUxLjMxMDM0NDggMCI+PC9wb2x5Z29uPgogICAgICAgICAgICA8cG9seWdvbiBpZD0iUmVjdGFuZ2xlIiBmaWxsPSIjRjdFM0FGIiBwb2ludHM9IjI3IDAgMzUgMCAzNyAxNCAyNSAxNCI+PC9wb2x5Z29uPgogICAgICAgIDwvZz4KICAgIDwvZz4KPC9zdmc+)](https://github.com/apple/swift-package-manager)

This framework is a wrapper around Apple's CommonCrypto and Security frameworks as well as OpenSSL. It tries to maintain Apple's CryptoKit semantics, function names, etc. It's designed to provide easy fallback for the devices, which do not support CryptoKit directly. It implements more convenient and memory optimised algorithms for file encryption than Apple's CryptoKit. However, when convenient it's recommended to use CryptoKit as it's a more modern design under the hood and should provide better preformance and efficiency. CommonCryptoKit depends on OpenSSL which adds more complexity and greatly increases the final executable size, it also adds more paperwork when distributing the app through App Store.

## 💻 Requirements

This framework works on all Apple devices with the minimum system requirements:
    * 📱 iOS 10.0+
    * 📺 tvOS 10.0+
    * ⌚️ watchOS 3.0+
    * 💻 macOS 10.12+

## 📖 Usage

This is a pre-release software. Some funcionality might be not available or might change over time. Please look at the CryptoKit usage for information about functions and available APIs.

## ⚖️ Export Compliance

This framework depends on OpenSSL, which means you should file a French Encryption Declaration if your app will be available in the French App Store.
Because all algotithms used and implemented here are standards, this means you are exempt from other Encryption Declarations when uploading to App Store.
OpenSSL as well as CommonCryptoKit is open-source, so you might apply for the "open-source" exemption if your app is also open-source.
