// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
//
// SPDX-License-Identifier: Apache-2.0

package v1alpha1

import (
	"context"

	"sigs.k8s.io/controller-runtime/pkg/client"
)

const admissionListPageLimit int64 = 100

func listAdmissionPage(
	ctx context.Context,
	reader client.Reader,
	list client.ObjectList,
	continueToken string,
	opts ...client.ListOption,
) (string, error) {
	listOpts := make([]client.ListOption, 0, len(opts)+2)
	listOpts = append(listOpts, opts...)
	listOpts = append(listOpts, client.Limit(admissionListPageLimit))
	if continueToken != "" {
		listOpts = append(listOpts, client.Continue(continueToken))
	}
	if err := reader.List(ctx, list, listOpts...); err != nil {
		return "", err
	}
	return list.GetContinue(), nil
}
