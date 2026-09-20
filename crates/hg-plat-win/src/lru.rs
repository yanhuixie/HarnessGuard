//! FileObject→文件名 缓存的 LRU 封顶（M1 缺口 1 缓解第一步；§10 预算表超支预案
//! 原文"FileObject 缓存加 LRU 上限"）。
//!
//! M1 实现：HashMap + 超限整表清空——burst 场景（cmd/tar 连续打开）会把最热
//! 条目一并清掉，紧接着的 Read/Write 全部 unknown。改为 O(1) 真逐出 LRU：
//! slab + 双向链表（下标链接，无 unsafe），get 即触达（移到 MRU 端），满则逐出
//! LRU 端。容量 200k 与 M1 相同（条目为 NT 路径字符串，均值 ~80B；相比 HashMap
//! 增量仅每条目两个 u32 链接 ≈ 1.6MB）。

use std::collections::HashMap;

struct Entry {
    key: u64,
    val: String,
    /// 双向链表（slab 下标）；None 为链端
    prev: Option<u32>,
    next: Option<u32>,
}

pub struct LruCache {
    entries: Vec<Entry>,
    /// slab 空洞复用栈
    free: Vec<u32>,
    map: HashMap<u64, u32>,
    /// MRU 端（最近使用）
    head: Option<u32>,
    /// LRU 端（逐出端）
    tail: Option<u32>,
    cap: usize,
}

impl LruCache {
    pub fn new(cap: usize) -> Self {
        Self {
            entries: Vec::new(),
            free: Vec::new(),
            map: HashMap::new(),
            head: None,
            tail: None,
            cap,
        }
    }

    pub fn len(&self) -> usize {
        self.map.len()
    }

    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }

    /// 查询并触达（移到 MRU 端）。
    pub fn get(&mut self, key: u64) -> Option<&str> {
        let idx = *self.map.get(&key)?;
        self.touch(idx);
        Some(self.entries[idx as usize].val.as_str())
    }

    /// 仅查询不触达（存在性检查，如探测失败表）。
    pub fn contains(&self, key: u64) -> bool {
        self.map.contains_key(&key)
    }

    fn touch(&mut self, idx: u32) {
        if self.head == Some(idx) {
            return;
        }
        let (prev, next) = (
            self.entries[idx as usize].prev,
            self.entries[idx as usize].next,
        );
        // 摘出
        if let Some(p) = prev {
            self.entries[p as usize].next = next;
        } else {
            self.tail = next;
        }
        if let Some(n) = next {
            self.entries[n as usize].prev = prev;
        }
        // 接到 MRU 端
        let old_head = self.head;
        self.entries[idx as usize].prev = old_head;
        self.entries[idx as usize].next = None;
        if let Some(h) = old_head {
            self.entries[h as usize].next = Some(idx);
        } else {
            self.tail = Some(idx);
        }
        self.head = Some(idx);
    }

    /// 插入/覆盖（覆盖时触达）。容量满则逐出 LRU 端条目。
    pub fn insert(&mut self, key: u64, val: String) {
        if let Some(&idx) = self.map.get(&key) {
            self.entries[idx as usize].val = val;
            self.touch(idx);
            return;
        }
        if self.map.len() >= self.cap && self.evict_lru().is_none() {
            return; // cap == 0：拒绝插入，防死循环（&& 短路保证仅在满时逐出）
        }
        let idx = match self.free.pop() {
            Some(i) => {
                self.entries[i as usize] = Entry {
                    key,
                    val,
                    prev: self.head,
                    next: None,
                };
                i
            }
            None => {
                self.entries.push(Entry {
                    key,
                    val,
                    prev: self.head,
                    next: None,
                });
                (self.entries.len() - 1) as u32
            }
        };
        if let Some(h) = self.head {
            self.entries[h as usize].next = Some(idx);
        } else {
            self.tail = Some(idx);
        }
        self.head = Some(idx);
        self.map.insert(key, idx);
    }

    /// 逐出 LRU 端并回收 slab 槽位。
    fn evict_lru(&mut self) -> Option<u64> {
        let tail = self.tail?;
        let key = self.entries[tail as usize].key;
        let next = self.entries[tail as usize].next;
        self.map.remove(&key);
        self.entries[tail as usize] = Entry {
            key: 0,
            val: String::new(),
            prev: None,
            next: None,
        };
        self.free.push(tail);
        self.tail = next;
        if let Some(n) = next {
            self.entries[n as usize].prev = None;
        } else {
            self.head = None; // 链空
        }
        Some(key)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn 容量封顶_超限逐出最久未用() {
        let mut c = LruCache::new(3);
        for i in 0..5u64 {
            c.insert(i, format!("v{i}"));
        }
        assert_eq!(c.len(), 3, "长度不得超容量");
        // 最后插入的 2/3/4 存活，0/1 已逐出
        assert!(c.contains(2) && c.contains(3) && c.contains(4));
        assert!(!c.contains(0) && !c.contains(1));
    }

    #[test]
    fn get触达_热点条目在burst下存活() {
        let mut c = LruCache::new(3);
        c.insert(1, "hot".into());
        for i in 10..30u64 {
            c.insert(i, "x".into());
            assert_eq!(c.get(1), Some("hot"), "持续触达的条目不得被逐出");
        }
        assert_eq!(c.len(), 3);
    }

    #[test]
    fn 覆盖同键_更新值且触达() {
        let mut c = LruCache::new(2);
        c.insert(1, "a".into());
        c.insert(2, "b".into());
        c.insert(1, "a2".into()); // 覆盖并触达 → 2 变为 LRU 端
        c.insert(3, "c".into()); // 逐出 2
        assert_eq!(c.get(1), Some("a2"));
        assert!(c.contains(3));
        assert!(!c.contains(2));
    }

    #[test]
    fn get未命中返回空_不触达() {
        let mut c = LruCache::new(2);
        c.insert(1, "a".into());
        c.insert(2, "b".into());
        assert!(c.get(999).is_none());
        assert_eq!(c.len(), 2);
    }

    #[test]
    fn 逐出到空链后再插入() {
        let mut c = LruCache::new(1);
        c.insert(1, "a".into());
        c.insert(2, "b".into()); // 逐出 1，链只剩 2
        c.insert(3, "c".into()); // 逐出 2
        assert_eq!(c.len(), 1);
        assert_eq!(c.get(3), Some("c"));
    }

    #[test]
    fn slab槽位复用不泄漏() {
        let mut c = LruCache::new(3);
        for i in 0..100u64 {
            c.insert(i, format!("v{i}"));
        }
        assert_eq!(c.len(), 3);
        assert!(
            c.entries.len() <= 3,
            "slab 槽位须复用，实际 {}",
            c.entries.len()
        );
    }

    #[test]
    fn 零容量拒绝插入() {
        let mut c = LruCache::new(0);
        c.insert(1, "a".into());
        assert!(c.is_empty());
    }
}
