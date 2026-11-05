import { useParams } from 'react-router-dom'
import { useEffect, useState } from 'react'
import { ReactFlow, Controls, Background, MiniMap } from 'reactflow'
import 'reactflow/dist/style.css'
import api from '../api/index'

export default function EntityGraph() {
  const { id } = useParams()
  const [nodes, setNodes] = useState([])
  const [edges, setEdges] = useState([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(null)

  useEffect(() => {
    api
      .get(`/api/investigations/${id}/entities/`)
      .then((res) => {
        const entityNodes = res.data.map((entity, i) => ({
          id: `entity-${i}`,
          type: 'entityNode',
          data: { label: entity.value, type: entity.entity_type },
          position: { x: 250 + i * 150, y: 100 },
        }))
        setNodes(entityNodes)
        setEdges([])
        setLoading(false)
      })
      .catch((err) => setError(err.message))
  }, [id])

  if (loading) {
    return (
      <div className="flex items-center justify-center h-64">
        <p className="text-slate-400">Loading entity graph...</p>
      </div>
    )
  }

  if (error) {
    return (
      <div className="card p-8 text-center">
        <p className="text-sm text-slate-400">{error}</p>
      </div>
    )
  }

  const nodeTypes = {
    entityNode: ({ data }) => (
      <div className="p-3 rounded-lg bg-teal-500/10 border border-teal-500/30 text-teal-400 text-sm font-medium">
        {data.label}
        <div className="text-xs text-slate-500 mt-1 capitalize">{data.type}</div>
      </div>
    ),
  }

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold text-white">Entity Relationship Graph</h1>
        <p className="text-slate-400">Case #{id}</p>
      </div>
      <div className="card h-[600px] flex flex-col">
        <div className="flex items-center justify-between p-4 border-b border-white/10">
          <h3 className="font-semibold text-white">Entities</h3>
          <p className="text-xs text-slate-400">{nodes.length} entity(ies) extracted</p>
        </div>
        <div className="flex-1">
          <ReactFlow
            nodes={nodes}
            edges={edges}
            nodeTypes={nodeTypes}
            fitViewOnInit={true}
          >
            <Controls />
            <MiniMap />
            <Background variant="dots" gap={4} />
          </ReactFlow>
        </div>
      </div>
    </div>
  )
}