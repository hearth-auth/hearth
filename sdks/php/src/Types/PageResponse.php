<?php

declare(strict_types=1);

namespace Hearth\Types;

/**
 * Paginated list response envelope.
 *
 * @template T
 */
final class PageResponse
{
    /**
     * @param list<T>     $items      Items on the current page
     * @param string|null $nextCursor Opaque cursor for the next page; null when no more pages exist
     */
    public function __construct(
        public readonly array $items,
        public readonly ?string $nextCursor = null,
    ) {}

    /** Returns true if there is another page of results. */
    public function hasNextPage(): bool
    {
        return $this->nextCursor !== null;
    }

    /**
     * Construct from a raw paginated JSON response body.
     *
     * @param array<string, mixed>     $data
     * @param callable(array<string, mixed>): T $itemFactory Transforms each raw item into the typed T
     * @return self<T>
     */
    public static function fromArray(array $data, callable $itemFactory): self
    {
        /** @var list<T> $items */
        $items = array_map($itemFactory, (array) ($data['items'] ?? []));

        return new self(
            items: $items,
            nextCursor: isset($data['next_cursor']) ? (string) $data['next_cursor'] : null,
        );
    }
}
