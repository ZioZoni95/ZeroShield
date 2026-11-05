// Copyright (c) 2026 ZioZoni95
// SPDX-License-Identifier: MIT

package xdp

import (
	"context"
	"errors"
	"time"

	"golang.org/x/sys/unix"
)

// WatchLinks avvisa (con un segnale su un canale) ogni volta che il kernel annuncia un cambio di interfacce, indirizzi
// o rotte IPv4/IPv6 tramite netlink. Serve a riagganciare il filtro subito quando collegi un adattatore o accendi il
// Wi-Fi, invece di aspettare il controllo periodico. E' solo un acceleratore: il controllo periodico resta come rete di
// sicurezza (un messaggio perso non lascia una rete scoperta per piu' di qualche secondo).
//
// Non richiede privilegi (solo ascolto). Il canale ha capienza 1: piu' eventi ravvicinati diventano un solo segnale.
func WatchLinks(ctx context.Context) (<-chan struct{}, error) {
	fd, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_RAW|unix.SOCK_CLOEXEC, unix.NETLINK_ROUTE)
	if err != nil {
		return nil, err
	}
	groups := uint32(unix.RTMGRP_LINK | unix.RTMGRP_IPV4_IFADDR | unix.RTMGRP_IPV6_IFADDR | unix.RTMGRP_IPV4_ROUTE | unix.RTMGRP_IPV6_ROUTE)
	if err := unix.Bind(fd, &unix.SockaddrNetlink{Family: unix.AF_NETLINK, Groups: groups}); err != nil {
		unix.Close(fd)
		return nil, err
	}
	// Timeout di lettura: cosi' il ciclo controlla ctx senza dover chiudere il socket da un'altra goroutine.
	tv := unix.NsecToTimeval(int64(time.Second))
	if err := unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &tv); err != nil {
		unix.Close(fd)
		return nil, err
	}
	out := make(chan struct{}, 1)
	go func() {
		defer unix.Close(fd)
		defer close(out)
		buf := make([]byte, 1<<16)
		for ctx.Err() == nil {
			n, _, err := unix.Recvfrom(fd, buf, 0)
			if err != nil {
				if errors.Is(err, unix.EAGAIN) || errors.Is(err, unix.EINTR) {
					continue // timeout: ricontrolla ctx
				}
				if errors.Is(err, unix.ENOBUFS) { // troppi messaggi: sicuramente e' cambiato qualcosa
					select {
					case out <- struct{}{}:
					default:
					}
					continue
				}
				return
			}
			if n > 0 {
				select {
				case out <- struct{}{}:
				default:
				}
			}
		}
	}()
	return out, nil
}
