// from https://github.com/paulmillr/noble-secp256k1/blob/main/index.ts#L803
const hexToBytes = (hex) => {
  if (typeof hex !== 'string') {
    throw new TypeError('hexToBytes: expected string, got ' + typeof hex)
  }
  if (hex.length % 2) throw new Error('hexToBytes: received invalid unpadded hex' + hex.length)
  const array = new Uint8Array(hex.length / 2)
  for (let i = 0; i < array.length; i++) {
    const j = i * 2
    const hexByte = hex.slice(j, j + 2)
    const byte = Number.parseInt(hexByte, 16)
    if (Number.isNaN(byte) || byte < 0) throw new Error('Invalid byte sequence')
    array[i] = byte
  }
  return array
}

const nip52hexa = async (addr) => {
  if (!/^.+@.+$/.test(addr)) return ''
  const [name, domain] = pubkey.split('@')
  const url = `https://${domain}/.well-known/nostr.json?name=${name}`
  const res = await fetch(url)
  if (!res.ok) return ''
  const data = await res.json()
  if (!data || !data.names || !data.names[name]) return ''
  return data.names[name]
}

// decode nip19 ('npub') to hex
const npub2hexa = (npub) => {
  let { prefix, words } = bech32.bech32.decode(npub, 90)
  if (prefix === 'npub') {
    let data = new Uint8Array(bech32.bech32.fromWords(words))
    return buffer.Buffer.from(data).toString('hex')
  }
}

// encode hex to nip19 ('npub')
const hexa2npub = (hex) => {
  const data = hexToBytes(hex)
  const words = bech32.bech32.toWords(data)
  const prefix = 'npub'
  return bech32.bech32.encode(prefix, words, 90)
}

// parse inserted pubkey
const parsePubkey = (pubkey) => (pubkey.match('npub1') ? npub2hexa(pubkey) : pubkey)

// download js file
const downloadFile = (data, fileName) => {
  const prettyJs = 'const data = ' + JSON.stringify(data, null, 2)
  const tempLink = document.createElement('a')
  const taBlob = new Blob([prettyJs], { type: 'text/javascript' })
  tempLink.setAttribute('href', URL.createObjectURL(taBlob))
  tempLink.setAttribute('download', fileName)
  tempLink.click()
}

// fetch events from relay, returns a promise
const fetchFromRelay = async (relay, filter, events) =>
  new Promise((resolve, reject) => {
    try {
      // prevent hanging forever
      setTimeout(() => reject('timeout'), 20_000)
      // open websocket
      const ws = new WebSocket(relay)
      // subscription id
      const subsId = 'my-sub'
      // subscribe to events filtered by author
      ws.onopen = () => {
        ws.send(JSON.stringify(['REQ', subsId, filter]))
      }

      // Listen for messages
      ws.onmessage = (event) => {
        const [msgType, subscriptionId, data] = JSON.parse(event.data)
        // event messages
        if (msgType === 'EVENT' && subscriptionId === subsId) {
          const { id } = data
          // prevent duplicated events
          if (events[id]) return
          else events[id] = data
          // show how many events were found until this moment
          const numEvents = Object.keys(events).length
          $('#events-found').text(`${numEvents} ${numEvents > 1 ? 'events' : 'event'} found`)
        }
        // end of subscription messages
        if (msgType === 'EOSE' && subscriptionId === subsId) resolve()
      }
      ws.onerror = (err) => reject(err)
    } catch (exception) {
      reject(exception)
    }
  })

// query relays for events published by this pubkey
const getEvents = async (filter) => {
  // events hash
  const events = {}
  // wait for all relays to finish
  await Promise.allSettled(relays.map((relay) => fetchFromRelay(relay, filter, events)))
  // return data as an array of events
  return Object.keys(events).map((id) => events[id])
}

const getEvent = async (filter) => {
  // events hash
  const events = {}
  // return as soon as one relay has found the event
  await new Promise((resolve) => {
    relays.map((relay) => fetchFromRelay(relay, filter, events).then(resolve))
  })
  // return event
  return Object.keys(events).map((id) => events[id])[0]
}

// send events to a relay, returns a promisse
const sendToRelay = async (relay, data) =>
  new Promise((resolve, reject) => {
    try {
      // prevent hanging forever
      setTimeout(() => reject('timeout'), 20_000)
      const ws = new WebSocket(relay)
      // fetch events from relay
      ws.onopen = () => {
        for (evnt of data) {
          ws.send(JSON.stringify(['EVENT', evnt]))
        }
        ws.close()
        resolve(`done for ${relay}`)
      }
      ws.onerror = (err) => reject(err)
    } catch (exception) {
      reject(exception)
    }
  })

// broadcast events to list of relays
const broadcastEvents = async (data) => {
  await Promise.allSettled(relays.map((relay) => sendToRelay(relay, data)))
}

const nip19ToHex = (id) => {
  const { prefix, words } = bech32.bech32.decode(id, id.length)
  if (!['note', 'nevent'].includes(prefix)) return
  const data = new Uint8Array(bech32.bech32.fromWords(words))
  if (prefix === 'note') {
    return {
      id: buffer.Buffer.from(data).toString('hex'),
    }
  }
  if (prefix === 'nevent') {
    let tlv = parseTLV(data)
    if (!tlv[0]?.[0]) throw new Error('missing TLV 0 for nevent')
    if (tlv[0][0].length !== 32) throw new Error('TLV 0 should be 32 bytes')
    return {
      id: buffer.Buffer.from(tlv[0][0]).toString('hex'),
    }
  }
}

const parseTLV = (data) => {
  let result = {}
  let rest = data
  while (rest.length > 0) {
    let t = rest[0]
    let l = rest[1]
    let v = rest.slice(2, 2 + l)
    rest = rest.slice(2 + l)
    if (v.length < l) throw new Error(`not enough data to read on TLV ${t}`)
    result[t] = result[t] || []
    result[t].push(v)
  }
  return result
}

const sha256 = async (message) => {
  const encoder = new TextEncoder()
  const data = encoder.encode(message)
  const hash = await crypto.subtle.digest('SHA-256', data)
  return Array.from(new Uint8Array(hash))
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('')
}

const calculateEventID = async (event) => {
  const eventData = JSON.stringify([0, event.pubkey, event.created_at, event.kind, event.tags, event.content])
  const hash = await sha256(eventData)
  return hash
}
