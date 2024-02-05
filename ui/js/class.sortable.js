/*
** Zabbix
** Copyright (C) 2001-2024 Zabbix SIA
**
** This program is free software; you can redistribute it and/or modify
** it under the terms of the GNU General Public License as published by
** the Free Software Foundation; either version 2 of the License, or
** (at your option) any later version.
**
** This program is distributed in the hope that it will be useful,
** but WITHOUT ANY WARRANTY; without even the implied warranty of
** MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
** GNU General Public License for more details.
**
** You should have received a copy of the GNU General Public License
** along with this program; if not, write to the Free Software
** Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
**/


class CSortable {

	/**
	 * Class applied to a sortable container.
	 *
	 * @type {string}
	 */
	static ZBX_STYLE_CLASS = 'sortable';

	/**
	 * Class applied to a sortable container while item is being dragged.
	 *
	 * @type {string}
	 */
	static ZBX_STYLE_DRAGGING = 'sortable-dragging';

	/**
	 * Class applied to item elements.
	 *
	 * @type {string}
	 */
	static ZBX_STYLE_ITEM = 'sortable-item';

	/**
	 * Class applied to elements of non-frozen items which still cannot be sorted.
	 *
	 * @type {string}
	 */
	static ZBX_STYLE_ITEM_DISABLED = 'sortable-item-disabled';

	/**
	 * Class applied to item elements while it is being dragged.
	 *
	 * @type {string}
	 */
	static ZBX_STYLE_ITEM_DRAGGING = 'sortable-item-dragging';

	/**
	 * Event fired on start of dragging of an item.
	 *
	 * @type {string}
	 */
	static EVENT_DRAG_START = 'sortable-drag-start';

	/**
	 * Event fired on end of dragging of an item.
	 *
	 * @type {string}
	 */
	static EVENT_DRAG_END = 'sortable-drag-end';

	/**
	 * Event fired on end of dragging of an item, if sort order has changed.
	 *
	 * @type {string}
	 */
	static EVENT_SORT = 'sortable-sort';

	static ANIMATION_SCROLL = 'scroll';

	static LISTENERS_OFF = 'off';
	static LISTENERS_SCROLL = 'scroll';
	static LISTENERS_SCROLL_SORT = 'scroll-sort';

	#target;

	#is_horizontal;

	#selector_span;
	#selector_freeze;
	#selector_handle;

	#is_enabled = false;
	#is_enabled_sorting;

	#animation_speed;
	#animation_time_limit;

	#items = [];
	#items_loc = [];
	#items_dim = new Map();
	#items_gap = new Map();

	#animations = new Map();
	#animation_frame = null;

	#scroll_pos = 0;

	#is_dragging = false;
	#drag_item = null;
	#drag_index = -1;
	#drag_index_original = -1;
	#drag_delta = 0;
	#drag_style;
	#overtake_items_loc = [];
	#overtake_min = -1;
	#overtake_max = -1;

	#drag_scroll_timeout = null;
	#drag_scroll_direction = 0;

	#mutation_observer;
	#mutation_observer_connected = false;

	#skip_click = false;

	/**
	 * Create CSortable instance.
	 *
	 * @param {HTMLElement} target                Sortable container.
	 * @param {boolean}     is_horizontal         Whether sorting is horizontally oriented.
	 * @param {string}      selector_span         Selector for matching first child element of multi-element items.
	 * @param {string}      selector_freeze       Selector for matching frozen items (cannot change order).
	 * @param {string}      selector_handle       Selector for matching a drag handle.
	 * @param {boolean}     enable                Whether to enable the instance initially.
	 * @param {boolean}     enable_sorting        Whether to enable sorting initially (or just scrolling).
	 * @param {number}      animation_speed       Animation speed in pixels per second.
	 * @param {number}      animation_time_limit  Animation time limit in seconds.
	 *
	 * @returns {CSortable}
	 */
	constructor(target, {
		is_horizontal = false,

		selector_span = '',
		selector_freeze = '',
		selector_handle = '',

		enable = true,
		enable_sorting = true,

		animation_speed = 500,
		animation_time_limit = .25
	} = {}) {
		this.#target = target;
		this.#target.classList.add(CSortable.ZBX_STYLE_CLASS);
		this.#target[is_horizontal ? 'scrollLeft' : 'scrollTop'] = 0;

		this.#is_horizontal = is_horizontal;

		this.#selector_span = selector_span;
		this.#selector_freeze = selector_freeze;
		this.#selector_handle = selector_handle;

		this.#is_enabled_sorting = enable_sorting;

		this.#animation_speed = animation_speed;
		this.#animation_time_limit = animation_time_limit;

		this.#mutation_observer = new MutationObserver(this.#listeners.mutation);

		if (enable) {
			this.enable();
		}
	}

	/**
	 * Get sortable container.
	 *
	 * @returns {HTMLElement}
	 */
	getTarget() {
		return this.#target;
	}

	/**
	 * Update items and reflect changes immediately.
	 *
	 * @param {function} callback  Scrollable container will be passed as the first parameter to the callback function.
	 */
	update(callback) {
		const enable = this.enable(false);

		callback(this.#target);

		this.enable(enable);
	}

	/**
	 * Enable or disable the instance.
	 *
	 * @param {boolean} enable
	 *
	 * @returns {boolean}  Previous state.
	 */
	enable(enable = true) {
		if (enable === this.#is_enabled) {
			return enable;
		}

		if (enable) {
			this.#updateItems();
			this.#render();
			this.#toggleListeners(CSortable.LISTENERS_SCROLL);
			this.#observeMutations();
		}
		else {
			this.#toggleListeners(CSortable.LISTENERS_OFF);
			this.#observeMutations(false);
			this.#cancelSorting();
		}

		this.#is_enabled = enable;

		return !enable;
	}

	/**
	 * Enable or disable sorting.
	 *
	 * @param {boolean} enable_sorting
	 *
	 * @returns {boolean}  Previous state.
	 */
	enableSorting(enable_sorting = true) {
		if (this.#is_enabled && this.#is_enabled_sorting && !enable_sorting) {
			this.#toggleListeners(CSortable.LISTENERS_SCROLL);
			this.#cancelSorting();
		}

		this.#is_enabled_sorting = enable_sorting;

		return !enable_sorting;
	}

	/**
	 * Scroll the target item into view.
	 *
	 * @param {HTMLElement} element
	 * @param {boolean}     immediate  Whether to scroll into view immediately.
	 */
	scrollIntoView(element, {immediate = false} = {}) {
		if (this.#is_dragging || this.#drag_item !== null) {
			return;
		}

		const item = this.#matchItem(element);

		if (item !== null) {
			this.#scrollIntoView(this.#items_loc.get(item));

			if (immediate) {
				this.#finishAnimations([CSortable.ANIMATION_SCROLL]);
			}
		}
	}

	/**
	 * Check whether the sortable container is scrollable.
	 *
	 * @returns {boolean}
	 */
	isScrollable() {
		return this.#getScrollMax() > 0;
	}

	/**
	 * Hard reset the instance.
	 */
	reset() {
		this.enable(false);
		this.#scrollTo(0);
		this.#finishAnimations();
	}

	#updateItems() {
		for (const item of this.#items) {
			this.#clearAnimation(item);
		}

		this.#items = [];
		this.#items_dim.clear();
		this.#items_gap.clear();

		for (const element of this.#target.querySelectorAll(':scope > *')) {
			if (this.#selector_span === '' || element.matches(this.#selector_span)) {
				this.#items.push({
					elements: [],
					freeze: this.#selector_freeze !== '' && element.matches(this.#selector_freeze),
					static: false,
					rel: 0
				});
			}

			this.#items.at(-1).elements.push(element);
		}

		this.#mutate(() => {
			for (let index = 0; index < this.#items.length; index++) {
				this.#items[index].static = this.#items[index].freeze
					|| ((index === 0 || this.#items[index - 1].freeze)
						&& (index === this.#items.length - 1 || this.#items[index + 1].freeze)
					);

				for (const element of this.#getContentsElements(this.#items[index].elements)) {
					element.classList.add(CSortable.ZBX_STYLE_ITEM);
					element.classList.toggle(CSortable.ZBX_STYLE_ITEM_DISABLED,
						!this.#items[index].freeze && this.#items[index].static
					);
				}
			}

			for (const item of this.#items) {
				this.#items_dim.set(item, this.#getLoc(item.elements).dim);
			}

			this.#items_loc = this.#getItemsLoc(this.#items);
			this.#fixItemsOrder();
		});
	}

	#getContentsElements(elements) {
		let contents_elements = [];

		for (const element of elements) {
			if (getComputedStyle(element).display === 'contents') {
				contents_elements = [...contents_elements, ...this.#getContentsElements(element.children)];
			}
			else {
				contents_elements.push(element);
			}
		}

		return contents_elements;
	}

	#getItemsLoc(items) {
		const items_loc = new Map();

		let pos = 0;

		for (let index = 0; index < items.length; index++) {
			const desc = this.#getItemGapDescriptor(items[index]);
			const desc_prev = index > 0 ? this.#getItemGapDescriptor(items[index - 1]) : null;

			if (!this.#items_gap.has(desc_prev)) {
				this.#items_gap.set(desc_prev, new Map());
			}

			if (!this.#items_gap.get(desc_prev).has(desc)) {
				this.#target.innerHTML = '';

				if (index > 0) {
					this.#target.append(...items[index - 1].elements);
				}

				this.#target.append(...items[index].elements);

				const loc = this.#getLoc(items[index].elements);
				const loc_prev = index > 0 ? this.#getLoc(items[index - 1].elements) : {pos: loc.pos, dim: 0};

				this.#items_gap.get(desc_prev).set(desc, loc.pos - loc_prev.pos - loc_prev.dim);
			}

			const gap = this.#items_gap.get(desc_prev).get(desc);
			const dim = this.#items_dim.get(items[index]);

			items_loc.set(items[index], {
				pos: pos + gap - items[index].rel,
				dim
			});

			pos += gap + dim;
		}

		return items_loc;
	}

	#fixItemsOrder() {
		this.#target.innerHTML = '';

		for (const item of this.#items) {
			this.#target.append(...item.elements);
		}
	}

	#getItemGapDescriptor(item) {
		return JSON.stringify(item.elements.map(element => [...element.classList].sort()));
	}

	#getTargetLoc() {
		const rect = this.#target.getBoundingClientRect();

		return {
			pos: this.#is_horizontal ? rect.x : rect.y,
			dim: this.#is_horizontal ? rect.width : rect.height
		};
	}

	#getLoc(elements) {
		let pos = 0;
		let pos_to = 0;

		for (const element of this.#getContentsElements(elements)) {
			const rect = element.getBoundingClientRect();

			const loc = {
				pos: this.#is_horizontal ? rect.x : rect.y,
				dim: this.#is_horizontal ? rect.width : rect.height
			};

			if (pos === 0 && pos_to === 0) {
				pos = loc.pos;
				pos_to = loc.pos + loc.dim;
			}
			else {
				pos = Math.min(pos, loc.pos);
				pos_to = Math.max(pos_to, loc.pos + loc.dim);
			}
		}

		return {
			pos,
			dim: pos_to - pos
		};
	}

	#getAnimation(key) {
		return this.#animations.get(key) ?? null;
	}

	#scheduleAnimation(key, from, to = null) {
		if (this.#animations.size === 0) {
			this.#animation_frame = requestAnimationFrame(() => this.#animate());
		}

		if (to === null) {
			to = from;
		}

		this.#animations.set(key, {
			from,
			to,
			time: performance.now(),
			duration: Math.min(this.#animation_time_limit, Math.abs(from - to) / this.#animation_speed) * 1000
		});
	}

	#clearAnimation(key) {
		this.#animations.delete(key);

		if (this.#animation_frame !== null && this.#animations.size === 0) {
			cancelAnimationFrame(this.#animation_frame);
			this.#animation_frame = null;
		}
	}

	#animate() {
		const time_now = performance.now();

		const updates = new Map();

		for (const [key, animation] of this.#animations) {
			const to = this.#getAnimationProgress(animation, time_now);

			updates.set(key, to);

			if (to === animation.to) {
				this.#animations.delete(key);
			}
		}

		this.#update(updates);
		this.#render();

		this.#animation_frame = this.#animations.size > 0
			? requestAnimationFrame(() => this.#animate())
			: null;
	}

	#finishAnimations(keys = null) {
		const updates = new Map();

		if (keys === null) {
			keys = this.#animations.keys();
		}

		for (const key of keys) {
			if (this.#animations.has(key)) {
				updates.set(key, this.#animations.get(key).to);

				this.#animations.delete(key);
			}
		}

		if (updates) {
			this.#update(updates);
			this.#render();

			if (this.#animations.size === 0 && this.#animation_frame !== null) {
				cancelAnimationFrame(this.#animation_frame);
				this.#animation_frame = null;
			}
		}
	}

	#getAnimationProgress({from, to, time, duration}, time_now) {
		if (time_now < time + duration && duration > 0) {
			const progress = (time_now - time) / duration;
			const progress_smooth = Math.sin(Math.PI * progress / 2);

			return from + (to - from) * progress_smooth;
		}

		return to;
	}

	#update(updates) {
		if (updates.has(CSortable.ANIMATION_SCROLL)) {
			this.#scroll_pos = updates.get(CSortable.ANIMATION_SCROLL);
		}

		for (const item of this.#items) {
			if (updates.has(item)) {
				item.rel = updates.get(item);
			}
		}
	}

	#render() {
		if (this.#is_dragging) {
			let drag_rel = this.#getDragRelConstrained();

			const drag_pos = this.#scroll_pos + this.#items_loc.get(this.#drag_item).pos + drag_rel;

			let index;

			for (index = this.#overtake_min; index < this.#overtake_max; index++) {
				const item_loc = [...this.#overtake_items_loc[index + 1].values()][index];

				if (item_loc.pos + item_loc.dim / 2 >= drag_pos) {
					break;
				}
			}

			if (index !== this.#drag_index) {
				this.#overtake(index);

				drag_rel = this.#getDragRelConstrained();
			}

			this.#applyRel(this.#drag_item.elements, drag_rel);
		}

		for (const item of this.#items) {
			if (!this.#is_dragging || item !== this.#drag_item) {
				this.#applyRel(item.elements, item.rel - this.#scroll_pos);
			}
		}
	}

	#matchItem(element) {
		for (const item of this.#items) {
			for (const item_element of item.elements) {
				if (item_element.contains(element)) {
					return item;
				}
			}
		}

		return null;
	}

	#applyRel(elements, rel) {
		for (const element of this.#getContentsElements(elements)) {
			element.style[this.#is_horizontal ? 'left' : 'top'] = `${rel}px`;
		}
	}

	#getDragConstraints() {
		const drag_loc = this.#items_loc.get(this.#drag_item);

		const overtake_min_loc = this.#items_loc.get(this.#items[this.#overtake_min]);
		const overtake_max_loc = this.#items_loc.get(this.#items[this.#overtake_max]);

		return {
			items: {
				min: overtake_min_loc.pos - drag_loc.pos - this.#scroll_pos,
				max: overtake_max_loc.pos + overtake_max_loc.dim - drag_loc.pos - drag_loc.dim - this.#scroll_pos
			},
			client: {
				min: -drag_loc.pos,
				max: this.#getTargetLoc().dim - drag_loc.pos - drag_loc.dim
			}
		};
	}

	#getDragRelConstrained(constraints = this.#getDragConstraints()) {
		const min = Math.max(constraints.items.min, constraints.client.min);
		const max = Math.min(constraints.items.max, constraints.client.max);

		return Math.max(Math.min(this.#drag_item.rel, max), min);
	}

	#overtake(index) {
		const drag_item_rel_delta = this.#items_loc.get(this.#drag_item).pos
			- this.#overtake_items_loc[index].get(this.#drag_item).pos;

		this.#drag_item.rel += drag_item_rel_delta;
		this.#drag_delta += drag_item_rel_delta;

		for (const [item, item_loc] of this.#overtake_items_loc[index]) {
			if (item !== this.#drag_item) {
				item.rel += this.#items_loc.get(item).pos - item_loc.pos;
				this.#scheduleAnimation(item, item.rel, 0);
			}
		}

		this.#mutate(() => {
			const item = this.#items[this.#drag_index];
			const item_to = this.#items[index];

			if (index > this.#drag_index) {
				item_to.elements.at(-1).after(...item.elements);
			}
			else {
				item_to.elements[0].before(...item.elements);
			}
		});

		this.#drag_index = index;
		this.#items = [...this.#overtake_items_loc[index].keys()];
		this.#items_loc = this.#overtake_items_loc[index];
	}

	#getScrollMax() {
		return this.#target[this.#is_horizontal ? 'scrollWidth' : 'scrollHeight'] - this.#getTargetLoc().dim;
	}

	#scrollTo(pos) {
		const animation = this.#getAnimation(CSortable.ANIMATION_SCROLL);

		const pos_cur = animation !== null
			? this.#getAnimationProgress(animation, performance.now())
			: this.#scroll_pos;

		const pos_to = Math.max(0, Math.min(this.#getScrollMax(), pos));

		this.#scheduleAnimation(CSortable.ANIMATION_SCROLL, pos_cur, pos_to);

		return pos_to - pos_cur;
	}

	#scrollRel(pos_rel) {
		const animation = this.#getAnimation(CSortable.ANIMATION_SCROLL);

		const pos_to = animation !== null ? animation.to : this.#scroll_pos;

		return this.#scrollTo(
			Math.sign(pos_rel) === Math.sign(pos_to - this.#scroll_pos)
				? pos_rel + pos_to
				: pos_rel + this.#scroll_pos
		);
	}

	#scrollIntoView({pos, dim}) {
		return this.#scrollTo(Math.min(pos, Math.max(this.#scroll_pos, pos + dim - this.#getTargetLoc().dim)));
	}

	#startDragging(client_pos) {
		this.#overtake_items_loc = [];

		this.#overtake_min = this.#drag_index;
		this.#overtake_max = this.#drag_index;

		while (this.#overtake_min >= 0 && !this.#items[this.#overtake_min].static) {
			this.#overtake_min--;
		}

		while (this.#overtake_max < this.#items.length && !this.#items[this.#overtake_max].static) {
			this.#overtake_max++;
		}

		this.#overtake_min++;
		this.#overtake_max--;

		this.#mutate(() => {
			for (let index = this.#overtake_min; index <= this.#overtake_max; index++) {
				const items = [...this.#items];

				items.splice(index, 0, ...items.splice(this.#drag_index, 1));

				this.#overtake_items_loc[index] = this.#getItemsLoc(items);
			}

			this.#fixItemsOrder();
		});

		this.#is_dragging = true;
		this.#drag_item.rel -= this.#scroll_pos;
		this.#drag_delta = this.#drag_item.rel - client_pos;

		this.#clearAnimation(this.#drag_item);
	}

	#endDragging() {
		this.#cancelDragScrolling();
		this.#scheduleAnimation(this.#drag_item, this.#scroll_pos + this.#getDragRelConstrained(), 0);
		this.#scrollIntoView(this.#items_loc.get(this.#drag_item));

		this.#is_dragging = false;
	}

	#startSorting(client_pos) {
		if (!this.#is_dragging) {
			this.#startDragging(client_pos);

			this.#mutate(() => {
				this.#target.classList.add(CSortable.ZBX_STYLE_DRAGGING);

				for (const element of this.#getContentsElements(this.#drag_item.elements)) {
					element.classList.add(CSortable.ZBX_STYLE_ITEM_DRAGGING);
				}
			});

			this.#drag_style = document.createElement('style');
			document.head.appendChild(this.#drag_style);
			this.#drag_style.sheet.insertRule(
				'* { pointer-events: none; user-select: none; cursor: grabbing !important; }'
			);

			this.#fire(CSortable.EVENT_DRAG_START, {index: this.#drag_index_original});
		}
	}

	#endSorting() {
		if (this.#is_dragging) {
			this.#endDragging();

			this.#mutate(() => {
				this.#target.classList.remove(CSortable.ZBX_STYLE_DRAGGING);

				for (const element of this.#getContentsElements(this.#drag_item.elements)) {
					element.classList.remove(CSortable.ZBX_STYLE_ITEM_DRAGGING);
				}
			});

			this.#drag_style.remove();

			this.#fire(CSortable.EVENT_DRAG_END, {index: this.#drag_index_original});

			if (this.#drag_index !== this.#drag_index_original) {
				this.#fire(CSortable.EVENT_SORT, {
					index: this.#drag_index_original,
					index_to: this.#drag_index
				});
			}

			this.#skip_click = true;
		}

		this.#drag_item = null;
	}

	#cancelSorting() {
		if (this.#is_dragging) {
			if (this.#drag_index !== this.#drag_index_original) {
				this.#overtake(this.#drag_index_original);
			}
		}

		this.#endSorting();
	}

	#requestDragScrolling(direction = this.#drag_scroll_direction) {
		if (this.#drag_scroll_timeout !== null) {
			clearTimeout(this.#drag_scroll_timeout);
		}

		this.#drag_scroll_direction = direction;

		this.#drag_scroll_timeout = setTimeout(() => {
			this.#drag_scroll_timeout = null;

			const index = this.#drag_index + this.#drag_scroll_direction;

			if (index >= this.#overtake_min && index <= this.#overtake_max) {
				this.#scrollIntoView(this.#items_loc.get(this.#items[index]));
				this.#requestDragScrolling();
			}
		}, this.#animation_time_limit * 1000);
	}

	#cancelDragScrolling() {
		if (this.#drag_scroll_timeout !== null) {
			clearTimeout(this.#drag_scroll_timeout);
			this.#drag_scroll_timeout = null;
		}
	}

	#toggleListeners(mode) {
		this.#target.removeEventListener('mousedown', this.#listeners.mouseDown);
		this.#target.removeEventListener('click', this.#listeners.click, {capture: true});
		this.#target.removeEventListener('wheel', this.#listeners.wheel);
		this.#target.removeEventListener('keydown', this.#listeners.keydown);
		this.#target.removeEventListener('focusin', this.#listeners.focusIn);

		removeEventListener('mousemove', this.#listeners.mouseMove);
		removeEventListener('mouseup', this.#listeners.mouseUp);
		removeEventListener('wheel', this.#listeners.wheel, {capture: true});

		switch (mode) {
			case CSortable.LISTENERS_SCROLL:
				this.#target.addEventListener('mousedown', this.#listeners.mouseDown);
				this.#target.addEventListener('wheel', this.#listeners.wheel);
				this.#target.addEventListener('keydown', this.#listeners.keydown);
				this.#target.addEventListener('focusin', this.#listeners.focusIn);

				break;

			case CSortable.LISTENERS_SCROLL_SORT:
				this.#target.addEventListener('mousedown', this.#listeners.mouseDown);
				this.#target.addEventListener('click', this.#listeners.click, {capture: true});

				addEventListener('mousemove', this.#listeners.mouseMove);
				addEventListener('mouseup', this.#listeners.mouseUp);
				addEventListener('wheel', this.#listeners.wheel, {passive: false, capture: true});

				break;
		}
	}

	#observeMutations(observe_mutations = true) {
		if (observe_mutations === this.#mutation_observer_connected) {
			return observe_mutations;
		}

		if (observe_mutations) {
			this.#mutation_observer.observe(this.#target, {
				subtree: true,
				childList: true,
				attributes: true,
				attributeFilter: ['class'],
				characterData: true
			});
		}
		else {
			this.#mutation_observer.disconnect();
		}

		this.#mutation_observer_connected = observe_mutations;

		return !observe_mutations;
	}

	#mutate(callback) {
		const rect = this.#target.getBoundingClientRect();

		this.#target.style.width = `${rect.width}px`;
		this.#target.style.height = `${rect.height}px`;

		const observe_mutations = this.#observeMutations(false);

		callback();

		this.#observeMutations(observe_mutations);

		this.#target.style.width = '';
		this.#target.style.height = '';
	}

	#listeners = {
		mouseDown: (e) => {
			const pos = this.#scroll_pos - this.#getTargetLoc().pos + (this.#is_horizontal ? e.clientX : e.clientY);

			this.#drag_item = null;

			for (const [item, item_loc] of this.#items_loc) {
				if (pos >= item_loc.pos + item.rel && pos < item_loc.pos + item_loc.dim + item.rel) {
					this.#scrollIntoView(item_loc);

					if (!this.#is_enabled_sorting || item.static) {
						break;
					}

					if (this.#selector_handle !== '') {
						const handle = e.target.closest(this.#selector_handle);

						if (handle === null || !this.#target.contains(handle)) {
							break;
						}
					}

					this.#drag_item = item;
					this.#drag_index = this.#items.indexOf(item);
					this.#drag_index_original = this.#drag_index;

					this.#toggleListeners(CSortable.LISTENERS_SCROLL_SORT);

					break;
				}
			}
		},

		mouseMove: (e) => {
			const client_pos = this.#is_horizontal ? e.clientX : e.clientY;

			this.#startSorting(client_pos);

			const rel_old = this.#drag_item.rel;

			this.#drag_item.rel = this.#drag_delta + client_pos;

			const constraints = this.#getDragConstraints();
			const rel_new = this.#getDragRelConstrained(constraints);

			if (rel_new === constraints.client.min && rel_new <= rel_old && this.#drag_item.rel < rel_new) {
				this.#requestDragScrolling(-1);
			}
			else if (rel_new === constraints.client.max && rel_new >= rel_old && this.#drag_item.rel > rel_new) {
				this.#requestDragScrolling(1);
			}
			else if (rel_new !== constraints.client.min && rel_new !== constraints.client.max) {
				this.#cancelDragScrolling();
			}

			this.#render();
		},

		mouseUp: () => {
			this.#toggleListeners(CSortable.LISTENERS_SCROLL);
			this.#endSorting();
		},

		click: (e) => {
			if (this.#skip_click) {
				this.#skip_click = false;

				e.stopPropagation();
			}
		},

		wheel: (e) => {
			if (!this.#is_dragging && this.#drag_item !== null) {
				const client_pos = this.#is_horizontal ? e.clientX : e.clientY;

				this.#startSorting(client_pos);
				this.#drag_item.rel = this.#drag_delta + client_pos;
			}

			this.#cancelDragScrolling();

			if (this.#scrollRel(e.deltaY !== 0 ? e.deltaY : e.deltaX) !== 0 || this.#is_dragging) {
				e.preventDefault();
			}

			if (this.#is_dragging) {
				e.stopPropagation();
			}
		},

		keydown: (e) => {
			if (!this.#is_enabled_sorting) {
				return;
			}

			let direction;

			if (e.ctrlKey && (e.key === 'ArrowLeft' || e.key === 'ArrowUp')) {
				direction = -1;
			}
			else if (e.ctrlKey && (e.key === 'ArrowRight' || e.key === 'ArrowDown')) {
				direction = 1;
			}
			else {
				return;
			}

			const item = this.#matchItem(e.target);

			if (item === null || item.static) {
				return;
			}

			e.preventDefault();

			const index = this.#items.indexOf(item);
			const index_to = index + direction;

			if (index_to < 0 || index_to > this.#items.length - 1 || this.#items[index_to].static) {
				return;
			}

			this.#mutate(() => {
				this.#items.splice(index, 0, ...this.#items.splice(index_to, 1));
				this.#items_loc = this.#getItemsLoc(this.#items);
				this.#fixItemsOrder();
			});

			e.target.focus();

			this.#fire(CSortable.EVENT_SORT, {index, index_to});
		},

		focusIn: (e) => {
			this.#target[this.#is_horizontal ? 'scrollLeft' : 'scrollTop'] = 0;

			const item = this.#matchItem(e.target);

			if (item !== null) {
				this.#scrollIntoView(this.#items_loc.get(item));
			}
		},

		mutation: () => {
			this.#toggleListeners(CSortable.LISTENERS_SCROLL);
			this.#cancelSorting();
			this.#updateItems();
			this.#render();
		}
	};

	/**
	 * Attach event listener.
	 *
	 * @param {string}       type
	 * @param {function}     listener
	 * @param {Object|false} options
	 *
	 * @returns {CSortable}
	 */
	on(type, listener, options = false) {
		this.#target.addEventListener(type, listener, options);

		return this;
	}

	/**
	 * Detach event listener.
	 *
	 * @param {string}       type
	 * @param {function}     listener
	 * @param {Object|false} options
	 *
	 * @returns {CSortable}
	 */
	off(type, listener, options = false) {
		this.#target.removeEventListener(type, listener, options);

		return this;
	}

	/**
	 * Dispatch event.
	 *
	 * @param {string} type
	 * @param {Object} detail
	 * @param {Object} options
	 *
	 * @returns {boolean}
	 */
	#fire(type, detail = {}, options = {}) {
		return this.#target.dispatchEvent(new CustomEvent(type, {...options, detail: {target: this, ...detail}}));
	}
}
