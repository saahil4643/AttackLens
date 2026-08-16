import React, { useState, useMemo } from 'react';
import { ChevronDown, ChevronUp, ChevronLeft, ChevronRight } from 'lucide-react';

export interface Column<T> {
  header: string;
  key: string;
  render?: (item: T) => React.ReactNode;
  sortable?: boolean;
}

interface DataTableProps<T> {
  columns: Column<T>[];
  data: T[];
  searchQuery?: string;
  searchKeys?: (keyof T)[];
  pagination?: boolean;
  pageSize?: number;
  onRowClick?: (item: T) => void;
  emptyState?: React.ReactNode;
}

export function DataTable<T extends Record<string, any>>({
  columns,
  data,
  searchQuery = '',
  searchKeys = [],
  pagination = true,
  pageSize = 10,
  onRowClick,
  emptyState
}: DataTableProps<T>) {
  const [sortKey, setSortKey] = useState<string | null>(null);
  const [sortDirection, setSortDirection] = useState<'asc' | 'desc'>('asc');
  const [currentPage, setCurrentPage] = useState(1);

  // Sorting Handler
  const handleSort = (key: string) => {
    if (sortKey === key) {
      setSortDirection(sortDirection === 'asc' ? 'desc' : 'asc');
    } else {
      setSortKey(key);
      setSortDirection('asc');
    }
    setCurrentPage(1);
  };

  // 1. Filter data based on search query
  const filteredData = useMemo(() => {
    if (!searchQuery || searchKeys.length === 0) return data;
    const query = searchQuery.toLowerCase();

    return data.filter((item) =>
      searchKeys.some((key) => {
        const val = item[key];
        if (val === undefined || val === null) return false;
        return String(val).toLowerCase().includes(query);
      })
    );
  }, [data, searchQuery, searchKeys]);

  // 2. Sort data
  const sortedData = useMemo(() => {
    if (!sortKey) return filteredData;

    return [...filteredData].sort((a, b) => {
      let valA = a[sortKey];
      let valB = b[sortKey];

      // Handle null/undefined
      if (valA === undefined || valA === null) return 1;
      if (valB === undefined || valB === null) return -1;

      // Type conversion for comparison
      if (typeof valA === 'string') {
        return sortDirection === 'asc'
          ? valA.localeCompare(String(valB))
          : String(valB).localeCompare(valA);
      } else {
        return sortDirection === 'asc'
          ? (valA > valB ? 1 : -1)
          : (valB > valA ? 1 : -1);
      }
    });
  }, [filteredData, sortKey, sortDirection]);

  // 3. Paginate data
  const paginatedData = useMemo(() => {
    if (!pagination) return sortedData;
    const start = (currentPage - 1) * pageSize;
    return sortedData.slice(start, start + pageSize);
  }, [sortedData, currentPage, pagination, pageSize]);

  const totalPages = Math.ceil(sortedData.length / pageSize) || 1;
  const isRowClickable = typeof onRowClick === 'function';

  return (
    <div className="flex flex-col w-full">
      {/* Table grid */}
      <div className="overflow-x-auto border border-zinc-900 rounded-lg bg-zinc-950/30">
        <table className="min-w-full divide-y divide-zinc-900 text-left text-xs text-zinc-300">
          <thead className="bg-[#0c0c0e] text-zinc-400 font-bold uppercase tracking-wider">
            <tr>
              {columns.map((col) => {
                const isSorted = sortKey === col.key;
                return (
                  <th
                    key={col.key}
                    onClick={() => col.sortable && handleSort(col.key)}
                    className={`px-4 py-3 select-none ${
                      col.sortable ? 'cursor-pointer hover:text-zinc-200 transition' : ''
                    }`}
                  >
                    <div className="flex items-center gap-1.5">
                      {col.header}
                      {col.sortable && (
                        <span className="text-zinc-600">
                          {isSorted ? (
                            sortDirection === 'asc' ? (
                              <ChevronUp className="w-3.5 h-3.5 text-zinc-400" />
                            ) : (
                              <ChevronDown className="w-3.5 h-3.5 text-zinc-400" />
                            )
                          ) : (
                            <ChevronDown className="w-3.5 h-3.5 opacity-0 hover:opacity-100 transition" />
                          )}
                        </span>
                      )}
                    </div>
                  </th>
                );
              })}
            </tr>
          </thead>
          <tbody className="divide-y divide-zinc-900 bg-transparent">
            {paginatedData.length > 0 ? (
              paginatedData.map((item, rowIndex) => (
                <tr
                  key={item.id || rowIndex}
                  onClick={() => onRowClick && onRowClick(item)}
                  className={`transition ${
                    isRowClickable ? 'hover:bg-zinc-900/60 cursor-pointer' : 'hover:bg-zinc-950/40'
                  }`}
                >
                  {columns.map((col) => (
                    <td key={col.key} className="px-4 py-3.5 font-medium whitespace-nowrap">
                      {col.render ? col.render(item) : item[col.key]}
                    </td>
                  ))}
                </tr>
              ))
            ) : (
              <tr>
                <td colSpan={columns.length} className="px-4 py-8 text-center text-zinc-500">
                  {emptyState || 'No records found.'}
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>

      {/* Pagination controls */}
      {pagination && sortedData.length > pageSize && (
        <div className="flex items-center justify-between mt-4 px-1">
          <p className="text-xs text-zinc-500 font-medium">
            Showing <span className="text-zinc-400 font-semibold font-mono">{(currentPage - 1) * pageSize + 1}</span> to{' '}
            <span className="text-zinc-400 font-semibold font-mono">
              {Math.min(currentPage * pageSize, sortedData.length)}
            </span>{' '}
            of <span className="text-zinc-400 font-semibold font-mono">{sortedData.length}</span> records
          </p>
          <div className="flex items-center gap-1.5">
            <button
              onClick={() => setCurrentPage((p) => Math.max(1, p - 1))}
              disabled={currentPage === 1}
              className="p-1.5 border border-zinc-800 rounded bg-zinc-950 text-zinc-400 hover:text-zinc-200 disabled:opacity-30 disabled:hover:text-zinc-400 disabled:cursor-not-allowed transition cursor-pointer"
            >
              <ChevronLeft className="w-3.5 h-3.5" />
            </button>
            <span className="text-xs text-zinc-400 px-3 font-semibold font-mono">
              Page {currentPage} of {totalPages}
            </span>
            <button
              onClick={() => setCurrentPage((p) => Math.min(totalPages, p + 1))}
              disabled={currentPage === totalPages}
              className="p-1.5 border border-zinc-800 rounded bg-zinc-950 text-zinc-400 hover:text-zinc-200 disabled:opacity-30 disabled:hover:text-zinc-400 disabled:cursor-not-allowed transition cursor-pointer"
            >
              <ChevronRight className="w-3.5 h-3.5" />
            </button>
          </div>
        </div>
      )}
    </div>
  );
}
