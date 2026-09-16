/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import fs from 'node:fs'
import { Readable } from 'node:stream'
import { finished } from 'node:stream/promises'
import dns from 'node:dns/promises'
import net from 'node:net'
import { type Request, type Response, type NextFunction } from 'express'

import * as security from '../lib/insecurity'
import { UserModel } from '../models/user'
import * as utils from '../lib/utils'
import logger from '../lib/logger'

function isPrivateIPv4 (parts: number[]): boolean {
  const [a, b, c] = parts
  if (a === 0 || a === 10 || a === 127) return true
  if (a === 100 && b >= 64 && b <= 127) return true
  if (a === 169 && b === 254) return true
  if (a === 172 && b >= 16 && b <= 31) return true
  if (a === 192 && b === 0 && c === 0) return true
  if (a === 192 && b === 0 && c === 2) return true
  if (a === 192 && b === 88 && c === 99) return true
  if (a === 192 && b === 168) return true
  if (a === 198 && (b === 18 || b === 19)) return true
  if (a === 198 && b === 51 && c === 100) return true
  if (a === 203 && b === 0 && c === 113) return true
  if (a >= 224) return true
  return false
}

function parseIPv6 (ip: string): number[] | null {
  ip = ip.toLowerCase()
  if (ip.includes('.')) {
    const lastColon = ip.lastIndexOf(':')
    const v4Str = ip.slice(lastColon + 1)
    const v4Parts = v4Str.split('.').map(Number)
    if (v4Parts.length !== 4 || v4Parts.some(n => isNaN(n) || n < 0 || n > 255)) return null
    const v4Hex = ((v4Parts[0] << 8) | v4Parts[1]).toString(16) + ':' + ((v4Parts[2] << 8) | v4Parts[3]).toString(16)
    ip = ip.slice(0, lastColon + 1) + v4Hex
  }
  const parts = ip.split('::')
  if (parts.length > 2) return null
  const head = parts[0] ? parts[0].split(':').map(h => parseInt(h, 16)) : []
  const tail = parts[1] ? parts[1].split(':').map(h => parseInt(h, 16)) : []
  if (head.some(isNaN) || tail.some(isNaN)) return null
  if (parts.length === 2) {
    const missing = 8 - head.length - tail.length
    if (missing < 0) return null
    head.push(...new Array(missing).fill(0), ...tail)
  }
  if (head.length !== 8) return null
  const bytes: number[] = []
  for (const group of head) {
    if (group < 0 || group > 0xffff) return null
    bytes.push((group >> 8) & 0xff)
    bytes.push(group & 0xff)
  }
  return bytes
}

function isPrivateOrReservedIP (ip: string): boolean {
  if (net.isIPv4(ip)) {
    const parts = ip.split('.').map(Number)
    if (parts.length === 4 && parts.every(n => !isNaN(n) && n >= 0 && n <= 255)) {
      return isPrivateIPv4(parts)
    }
    return true
  }
  if (net.isIPv6(ip)) {
    const b = parseIPv6(ip)
    if (!b) return true
    if (b.slice(0, 15).every(x => x === 0) && b[15] === 1) return true
    if (b.every(x => x === 0)) return true
    if (b.slice(0, 10).every(x => x === 0) && b[10] === 0xff && b[11] === 0xff) {
      return isPrivateIPv4(b.slice(12, 16))
    }
    if (b.slice(0, 12).every(x => x === 0)) {
      return isPrivateIPv4(b.slice(12, 16))
    }
    if ((b[0] & 0xfe) === 0xfc) return true
    if (b[0] === 0xfe && (b[1] & 0xc0) === 0x80) return true
    if (b[0] === 0xff) return true
    if (b[0] === 0x20 && b[1] === 0x01 && b[2] === 0x0d && b[3] === 0xb8) return true
    if (b[0] === 0x01 && b[1] === 0x00 && b.slice(2, 8).every(x => x === 0)) return true
    return false
  }
  return true
}

async function isSafeUrl (urlString: string): Promise<boolean> {
  if (typeof urlString !== 'string' || !urlString.trim()) {
    return false
  }

  let parsed: URL
  try {
    parsed = new URL(urlString)
  } catch {
    return false
  }

  if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
    return false
  }

  const hostname = parsed.hostname.replace(/^\[|\]$/g, '').toLowerCase()
  if (!hostname) {
    return false
  }

  if (
    hostname === 'localhost' ||
    hostname.endsWith('.localhost') ||
    hostname.endsWith('.local') ||
    hostname.endsWith('.internal') ||
    hostname.endsWith('.lan') ||
    hostname.endsWith('.home.arpa')
  ) {
    return false
  }

  if (net.isIP(hostname)) {
    return !isPrivateOrReservedIP(hostname)
  }

  if (!hostname.includes('.')) {
    return false
  }

  try {
    const addresses = await dns.lookup(hostname, { all: true })
    if (!addresses || addresses.length === 0) {
      return false
    }
    for (const record of addresses) {
      if (isPrivateOrReservedIP(record.address)) {
        return false
      }
    }
  } catch {
    return false
  }

  return true
}

async function fetchSafeImage (initialUrl: string) {
  let currentUrl = initialUrl
  for (let redirectCount = 0; redirectCount < 5; redirectCount++) {
    if (!await isSafeUrl(currentUrl)) {
      throw new Error('Blocked illegal activity')
    }
    const response = await fetch(currentUrl, { redirect: 'manual' })
    if ([301, 302, 303, 307, 308].includes(response.status)) {
      const location = response.headers.get('location')
      if (!location) {
        throw new Error('Redirect without Location header')
      }
      currentUrl = new URL(location, currentUrl).toString()
      continue
    }
    return { response, finalUrl: currentUrl }
  }
  throw new Error('Too many redirects')
}

export function profileImageUrlUpload () {
  return async (req: Request, res: Response, next: NextFunction) => {
    if (req.body.imageUrl !== undefined) {
      const url = req.body.imageUrl
      const loggedInUser = security.authenticatedUsers.get(req.cookies.token)
      if (loggedInUser) {
        if (!await isSafeUrl(url)) {
          next(new Error('Blocked illegal activity by ' + req.socket.remoteAddress))
          return
        }
        try {
          const { response, finalUrl } = await fetchSafeImage(url)
          if (!response.ok || !response.body) {
            throw new Error('url returned a non-OK status code or an empty body')
          }
          const ext = ['jpg', 'jpeg', 'png', 'svg', 'gif'].includes(finalUrl.split('.').slice(-1)[0].toLowerCase()) ? finalUrl.split('.').slice(-1)[0].toLowerCase() : 'jpg'
          const fileStream = fs.createWriteStream(`frontend/dist/frontend/assets/public/images/uploads/${loggedInUser.data.id}.${ext}`, { flags: 'w' })
          await finished(Readable.fromWeb(response.body as any).pipe(fileStream))
          const user = await UserModel.findByPk(loggedInUser.data.id)
          await user?.update({ profileImage: `/assets/public/images/uploads/${loggedInUser.data.id}.${ext}` })
        } catch (error) {
          if (error instanceof Error && error.message.startsWith('Blocked')) {
            next(new Error('Blocked illegal activity by ' + req.socket.remoteAddress))
            return
          }
          try {
            const user = await UserModel.findByPk(loggedInUser.data.id)
            await user?.update({ profileImage: url })
            logger.warn(`Error retrieving user profile image: ${utils.getErrorMessage(error)}; using image link directly`)
          } catch (error) {
            next(error)
            return
          }
        }
      } else {
        next(new Error('Blocked illegal activity by ' + req.socket.remoteAddress))
        return
      }
    }
    res.location(process.env.BASE_PATH + '/profile')
    res.redirect(process.env.BASE_PATH + '/profile')
  }
}
