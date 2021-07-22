// SPDX-License-Identifier: GPL-2.0
/*
 * S1G handling
 * Copyright(c) 2020 Adapt-IP
 */
#include <linux/ieee80211.h>
#include <net/mac80211.h>
#include "ieee80211_i.h"
#include "driver-ops.h"

void ieee80211_s1g_sta_rate_init(struct sta_info *sta)
{
	/* avoid indicating legacy bitrates for S1G STAs */
	sta->tx_stats.last_rate.flags |= IEEE80211_TX_RC_S1G_MCS;
	sta->rx_stats.last_rate =
			STA_STATS_FIELD(TYPE, STA_STATS_RATE_TYPE_S1G);
}

bool ieee80211_s1g_is_twt_setup(struct sk_buff *skb)
{
	struct ieee80211_mgmt *mgmt = (struct ieee80211_mgmt *)skb->data;

	if (likely(!ieee80211_is_action(mgmt->frame_control)))
		return false;

	if (likely(mgmt->u.action.category != WLAN_CATEGORY_S1G))
		return false;

	return mgmt->u.action.u.s1g.action_code == WLAN_S1G_TWT_SETUP;
}

static int
ieee80211_s1g_send_twt_setup(struct ieee80211_sub_if_data *sdata,
			     const u8 *da, const u8 *bssid, u8 dialog_token,
			     struct ieee80211_twt_params *params)
{
	struct ieee80211_local *local = sdata->local;
	struct ieee80211_twt_setup *twt;
	struct ieee80211_mgmt *mgmt;
	struct sk_buff *skb;

	skb = dev_alloc_skb(local->hw.extra_tx_headroom +
			    IEEE80211_TWT_IND_SETUP_SIZE);
	if (!skb)
		return -ENOMEM;

	skb_reserve(skb, local->hw.extra_tx_headroom);
	mgmt = skb_put_zero(skb, IEEE80211_TWT_IND_SETUP_SIZE);
	mgmt->frame_control = cpu_to_le16(IEEE80211_FTYPE_MGMT |
					  IEEE80211_STYPE_ACTION);
	memcpy(mgmt->da, da, ETH_ALEN);
	memcpy(mgmt->sa, sdata->vif.addr, ETH_ALEN);
	memcpy(mgmt->bssid, bssid, ETH_ALEN);

	mgmt->u.action.category = WLAN_CATEGORY_S1G;
	mgmt->u.action.u.s1g.action_code = WLAN_S1G_TWT_SETUP;

	twt = (struct ieee80211_twt_setup *)mgmt->u.action.u.s1g.variable;
	twt->dialog_token = dialog_token;
	twt->element_id = WLAN_EID_S1G_TWT;
	twt->length = sizeof(struct ieee80211_twt_params);

	memcpy(twt->params, params, twt->length);

	IEEE80211_SKB_CB(skb)->flags |= IEEE80211_TX_INTFL_DONT_ENCRYPT |
					IEEE80211_TX_CTL_REQ_TX_STATUS;
	ieee80211_tx_skb(sdata, skb);

	return 0;
}

static int
ieee80211_s1g_send_twt_teardown(struct ieee80211_sub_if_data *sdata,
				const u8 *da, const u8 *bssid, u8 flowid)
{
	struct ieee80211_local *local = sdata->local;
	struct ieee80211_mgmt *mgmt;
	struct sk_buff *skb;
	u8 *id;

	skb = dev_alloc_skb(local->hw.extra_tx_headroom +
			    IEEE80211_MIN_ACTION_SIZE + 2);
	if (!skb)
		return -ENOMEM;

	skb_reserve(skb, local->hw.extra_tx_headroom);
	mgmt = skb_put_zero(skb, IEEE80211_MIN_ACTION_SIZE + 2);
	mgmt->frame_control = cpu_to_le16(IEEE80211_FTYPE_MGMT |
					  IEEE80211_STYPE_ACTION);
	memcpy(mgmt->da, da, ETH_ALEN);
	memcpy(mgmt->sa, sdata->vif.addr, ETH_ALEN);
	memcpy(mgmt->bssid, bssid, ETH_ALEN);

	mgmt->u.action.category = WLAN_CATEGORY_S1G;
	mgmt->u.action.u.s1g.action_code = WLAN_S1G_TWT_TEARDOWN;
	id = (u8 *)mgmt->u.action.u.s1g.variable;
	*id = flowid;

	IEEE80211_SKB_CB(skb)->flags |= IEEE80211_TX_INTFL_DONT_ENCRYPT |
					IEEE80211_TX_CTL_REQ_TX_STATUS;
	ieee80211_tx_skb(sdata, skb);

	return 0;
}

static int
ieee80211_s1g_rx_h_twt_setup(struct ieee80211_sub_if_data *sdata,
			     struct sta_info *sta, struct sk_buff *skb)
{
	struct ieee80211_mgmt *mgmt = (struct ieee80211_mgmt *)skb->data;
	struct ieee80211_twt_params *agrt_req, agrt_resp;
	struct ieee80211_twt_setup *twt;

	twt = (struct ieee80211_twt_setup *)mgmt->u.action.u.s1g.variable;
	if (twt->element_id != WLAN_EID_S1G_TWT)
		return -EINVAL;

	agrt_req = (struct ieee80211_twt_params *)twt->params;

	/* broadcast TWT not supported yet */
	if (agrt_req->control & IEEE80211_TWT_CONTROL_NEG_TYPE_BROADCAST)
		return -EINVAL;

	drv_add_twt_setup(sdata->local, sdata, &sta->sta, agrt_req,
			  &agrt_resp);

	return ieee80211_s1g_send_twt_setup(sdata, mgmt->sa, sdata->vif.addr,
					    twt->dialog_token, &agrt_resp);
}

static int
ieee80211_s1g_status_twt_setup(struct ieee80211_sub_if_data *sdata,
			       struct sta_info *sta, struct sk_buff *skb)
{
	struct ieee80211_mgmt *mgmt = (struct ieee80211_mgmt *)skb->data;
	struct ieee80211_twt_params *agrt_resp;
	struct ieee80211_twt_setup *twt;
	u8 flowid;

	twt = (struct ieee80211_twt_setup *)mgmt->u.action.u.s1g.variable;
	agrt_resp = (struct ieee80211_twt_params *)twt->params;
	flowid = FIELD_GET(IEEE80211_TWT_REQTYPE_FLOWID,
			   le16_to_cpu(agrt_resp->req_type));

	drv_twt_teardown_request(sdata->local, sdata, &sta->sta, flowid);

	return ieee80211_s1g_send_twt_teardown(sdata, mgmt->sa,
					       sdata->vif.addr, flowid);
}

static int
ieee80211_s1g_rx_h_twt_teardown(struct ieee80211_sub_if_data *sdata,
				struct sta_info *sta, struct sk_buff *skb)
{
	struct ieee80211_mgmt *mgmt = (struct ieee80211_mgmt *)skb->data;

	drv_twt_teardown_request(sdata->local, sdata, &sta->sta,
				 mgmt->u.action.u.s1g.variable[0]);

	return 0;
}

void ieee80211_s1g_rx_h_twt(struct ieee80211_sub_if_data *sdata,
			    struct sk_buff *skb)
{
	struct ieee80211_mgmt *mgmt = (struct ieee80211_mgmt *)skb->data;
	struct ieee80211_local *local = sdata->local;
	struct sta_info *sta;

	mutex_lock(&local->sta_mtx);

	sta = sta_info_get_bss(sdata, mgmt->sa);
	if (!sta)
		goto out;

	switch (mgmt->u.action.u.s1g.action_code) {
	case WLAN_S1G_TWT_SETUP:
		ieee80211_s1g_rx_h_twt_setup(sdata, sta, skb);
		break;
	case WLAN_S1G_TWT_TEARDOWN:
		ieee80211_s1g_rx_h_twt_teardown(sdata, sta, skb);
		break;
	default:
		break;
	}

out:
	mutex_unlock(&local->sta_mtx);
}

void ieee80211_s1g_status_h_twt(struct ieee80211_sub_if_data *sdata,
				struct sk_buff *skb)
{
	struct ieee80211_mgmt *mgmt = (struct ieee80211_mgmt *)skb->data;
	struct ieee80211_local *local = sdata->local;
	struct sta_info *sta;

	mutex_lock(&local->sta_mtx);

	sta = sta_info_get_bss(sdata, mgmt->da);
	if (!sta)
		goto out;

	switch (mgmt->u.action.u.s1g.action_code) {
	case WLAN_S1G_TWT_SETUP:
		ieee80211_s1g_status_twt_setup(sdata, sta, skb);
		break;
	default:
		break;
	}

out:
	mutex_unlock(&local->sta_mtx);
}
